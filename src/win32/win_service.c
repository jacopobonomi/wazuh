/* Copyright (C) Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "shared.h"
#include "os_win.h"
#include <winsvc.h>
#include <sddl.h>
#include <aclapi.h>
#include "syscheckd/src/db/include/db.h"
#ifndef ARGV0
#define ARGV0 "wazuh-agent"
#endif

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/winsvc_wrappers.h"
#include "unit_tests/wrappers/windows/fileapi_wrappers.h"
#include "unit_tests/wrappers/windows/synchapi_wrappers.h"
#include "unit_tests/wrappers/windows/errhandlingapi_wrappers.h"
#endif

/**************************************************************************************
    WARNING: all the logging functions of this file must use the plain_ variant
    to avoid calling any external library that could be loaded before the signature
    verification can be executed in local_start.
**************************************************************************************/

static LPTSTR g_lpszServiceName        = "WazuhSvc";
static LPTSTR g_lpszServiceDisplayName = "Wazuh";
static LPTSTR g_lpszServiceDescription = "Wazuh Windows Agent";

static SERVICE_STATUS          ossecServiceStatus;
static SERVICE_STATUS_HANDLE   ossecServiceStatusHandle;

void WINAPI OssecServiceStart (DWORD argc, LPTSTR *argv);
void wm_kill_children();
extern void stop_wmodules();
extern void wm_lifecycle_lock_init(void);

/* Reports shutdown progress to the SCM so a slow stop_wmodules() (module
 * joins, each up to their own budget) doesn't read as hung (issue 38428,
 * defect #7). No-op before RegisterServiceCtrlHandler() has succeeded. */
void report_stop_progress(DWORD checkpoint, DWORD wait_hint_ms)
{
    if (!ossecServiceStatusHandle) {
        return;
    }

    ossecServiceStatus.dwCheckPoint = checkpoint;
    ossecServiceStatus.dwWaitHint = wait_hint_ms;
    SetServiceStatus(ossecServiceStatusHandle, &ossecServiceStatus);
}

/* Start the agent service */
int os_start_service()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;

    /* Start the database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if (schService) {
            if (StartService(schService, 0, NULL)) {
                rc = 1;
            } else {
                if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                    rc = -1;
                }
            }

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return (rc);
}

/* Stop the agent service */
int os_stop_service()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;

    /* Stop the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if (schService) {
            SERVICE_STATUS lpServiceStatus;

            if (ControlService(schService, SERVICE_CONTROL_STOP, &lpServiceStatus)) {
                rc = 1;
            }
            else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
                rc = -1; /* already stopped — not a real error */
            }
            else if (GetLastError() == ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
                rc = -1; /* already stopping — wait and restart normally */
            }
            else {
                plain_mdebug1("os_stop_service(): ControlService failed (error %lu).", GetLastError());
            }

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    /*
    * Sleep for a short period of time to avoid possible race-conditions with
    * newer instances of wazuh-agent.
    */
    if (rc == 1 || rc == -1) {
        Sleep(300);
    }

    return (rc);
}

/* Check if the agent service is running, or in any state other
 * than fully stopped.
 *
 * Returns 1 if the service exists and is anything other than SERVICE_STOPPED
 * (this includes SERVICE_STOP_PENDING/SERVICE_START_PENDING/etc.), or 0 if
 * it's stopped or doesn't exist.
 *
 * Before issue 38428's fix this only returned 1 for SERVICE_RUNNING, which
 * made the "wait for the old process to actually die" loop in win_agent.c's
 * service-restart give up the instant the SCM reported SERVICE_STOP_PENDING
 * -- long before stop_wmodules() had actually finished -- so the new process
 * started up over the still-shutting-down old one. */
int CheckServiceRunning()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;

    /* Check service status */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if (schService) {
            /* Check status */
            SERVICE_STATUS lpServiceStatus;

            if (QueryServiceStatus(schService, &lpServiceStatus)) {
                if (lpServiceStatus.dwCurrentState != SERVICE_STOPPED) {
                    rc = 1;
                }
            }
            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return (rc);
}

/* Takes the lock that serializes service-restart invocations: tmp\service-restart.lock, opened with no
 * sharing, so it is held exactly as long as the process that opened it and released by the system if
 * that process dies. The file is left in place: deleting it on close would leave it delete-pending while
 * another handle (an antivirus scan) stays open, and an open in that window fails with
 * ERROR_ACCESS_DENIED instead of ERROR_SHARING_VIOLATION. Only Administrators and SYSTEM can create or open files in tmp\
 * (SetWazuhPermissions), so no other account can hold it -- unlike a named object, whose name any
 * account can take first.
 *
 * Retries every 500 ms while another restart holds it. Returns the handle, or INVALID_HANDLE_VALUE with
 * *timed_out set if it was still held after wait_ms, or INVALID_HANDLE_VALUE with *timed_out clear (and
 * the error in GetLastError()) if it could not be opened for any other reason. */
HANDLE acquire_restart_lock(DWORD wait_ms, int *timed_out)
{
    const DWORD retryMs = 500;
    DWORD waited = 0;

    *timed_out = 0;

    for (;;) {
        HANDLE lock = CreateFile("tmp\\service-restart.lock", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, NULL);

        if (lock != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION) {
            return lock;
        }

        if (waited >= wait_ms) {
            *timed_out = 1;
            return INVALID_HANDLE_VALUE;
        }

        Sleep(retryMs);
        waited += retryMs;
    }
}

/* Install the agent service */
int InstallService(char *path)
{
    int ret;
    SC_HANDLE schSCManager, schService;
    LPCTSTR lpszBinaryPathName = NULL;
    SERVICE_DESCRIPTION sdBuf;

    /* Uninstall service (if it exists) */
    if (!UninstallService()) {
        plain_merror("Failure running UninstallService().");
        return (0);
    }

    /* Executable path -- it must be called with the full path */
    lpszBinaryPathName = path;

    /* Opening the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (schSCManager == NULL) {
        goto install_error;
    }

    /* Create the service */
    schService = CreateService(schSCManager,
                               g_lpszServiceName,
                               g_lpszServiceDisplayName,
                               SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS,
                               SERVICE_AUTO_START,
                               SERVICE_ERROR_NORMAL,
                               lpszBinaryPathName,
                               NULL, NULL, NULL, NULL, NULL);

    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        goto install_error;
    }

    /* Set description */
    sdBuf.lpDescription = g_lpszServiceDescription;
    ret = ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sdBuf);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    /* Check for errors */
    if (!ret) {
        goto install_error;
    }

    plain_minfo("Successfully added to the service database.");
    return (1);

install_error: {
        char local_msg[1025];
        LPVOID lpMsgBuf;

        memset(local_msg, 0, 1025);

        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       GetLastError(),
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPTSTR) &lpMsgBuf,
                       0,
                       NULL);

        plain_merror("Unable to create service entry: %s", (LPCTSTR)lpMsgBuf);
        return (0);
    }
}

/* Uninstall the agent service */
int UninstallService()
{
    int ret;
    int rc = 0;
    SC_HANDLE schSCManager, schService;
    SERVICE_STATUS lpServiceStatus;

    /* Remove from the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (schService) {
            /* Query the raw state directly instead of CheckServiceRunning(): that
             * helper now treats anything but SERVICE_STOPPED as "running" (issue
             * 38428, to fix the restart-wait loop giving up too early), but here a
             * SERVICE_STOP_PENDING service can't accept a fresh SERVICE_CONTROL_STOP
             * -- ControlService() would fail with ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
             * skipping DeleteService() below and reporting the whole uninstall as
             * failed even though the service was already on its way out. */
            SERVICE_STATUS currentStatus;
            BOOL queried = QueryServiceStatus(schService, &currentStatus);
            DWORD currentState = queried ? currentStatus.dwCurrentState : SERVICE_RUNNING;

            if (queried && currentState == SERVICE_STOPPED) {
                plain_minfo("Found (%s) service is not running.", g_lpszServiceName);
                ret = 1;
            } else if (queried && currentState == SERVICE_STOP_PENDING) {
                plain_minfo("Found (%s) service is already stopping; waiting for it to finish.", g_lpszServiceName);

                const DWORD stopWaitTimeoutMs = 45000;
                const DWORD waitStart = GetTickCount();
                ret = 1;

                while (QueryServiceStatus(schService, &currentStatus) && currentStatus.dwCurrentState != SERVICE_STOPPED) {
                    if (GetTickCount() - waitStart > stopWaitTimeoutMs) {
                        plain_merror("Failure waiting for (%s) to finish stopping before removing it.", g_lpszServiceName);
                        ret = 0;
                        break;
                    }
                    Sleep(500);
                }
            } else {
                plain_minfo("Found (%s) service is running going to try and stop it.", g_lpszServiceName);
                ret = ControlService(schService, SERVICE_CONTROL_STOP, &lpServiceStatus);
                if (!ret) {
                    plain_merror("Failure stopping service (%s) before removing it (%ld).", g_lpszServiceName, GetLastError());
                } else {
                    plain_minfo("Successfully stopped (%s).", g_lpszServiceName);
                }
            }

            if (ret && DeleteService(schService)) {
                plain_minfo("Successfully removed (%s) from the service database.", g_lpszServiceName);
                rc = 1;
            }
            CloseServiceHandle(schService);
        } else {
            plain_minfo("Service does not exist (%s) nothing to remove.", g_lpszServiceName);
            rc = 1;
        }
        CloseServiceHandle(schSCManager);
    }

    if (!rc) {
        plain_merror("Failure removing (%s) from the service database.", g_lpszServiceName);
    }

    return (rc);
}

/* "Signal" handler */
VOID WINAPI OssecServiceCtrlHandler(DWORD dwOpcode)
{
    /* Re-entry guard: merror_exit() calls WinSetError() which re-enters this
     * handler. Without the guard the second pass runs stop_wmodules a second
     * time on top of the first, racing the SCM transitions. */
    static volatile LONG stop_in_progress = 0;

    if (ossecServiceStatusHandle) {
        switch (dwOpcode) {
            case SERVICE_CONTROL_STOP:
                if (InterlockedCompareExchange(&stop_in_progress, 1, 0) != 0) {
                    return;
                }

                ossecServiceStatus.dwWin32ExitCode          = 0;
                ossecServiceStatus.dwCheckPoint             = 0;
                /* The stop path below blocks: wm_kill_children(), stop_wmodules() and the FIM
                 * database teardown (FIM_TEARDOWN_BUDGET_MS). The wait hint provides a best-effort
                 * estimate to the SCM covering teardown and module shutdowns. */
                ossecServiceStatus.dwWaitHint               = FIM_TEARDOWN_BUDGET_MS + 10000;

                plain_minfo("Received exit signal. Starting exit process.");
#ifdef OSSECHIDS
                ossecServiceStatus.dwCurrentState           = SERVICE_STOP_PENDING;
                SetServiceStatus (ossecServiceStatusHandle, &ossecServiceStatus);
                plain_minfo("Set pending exit signal.");

                is_fim_shutdown = true;
                // Kill children processes spawned by modules, only in wazuh-agent
                wm_kill_children();
                stop_wmodules();
                // stop_wmodules()'s own join loop (win_utils.c) drives dwWaitHint down to a few
                // seconds at a time via report_stop_progress() -- appropriate while it's still
                // actively reporting every couple of seconds, but fim_db_teardown() below has no
                // progress reporting of its own and can run up to FIM_TEARDOWN_BUDGET_MS. Without
                // re-widening the hint here first, the SCM would only be covered for the last few
                // seconds stop_wmodules() reported, not this next phase (issue 38428).
                report_stop_progress(ossecServiceStatus.dwCheckPoint + 1, FIM_TEARDOWN_BUDGET_MS + 5000);
                fim_db_teardown();
#endif
                // report_stop_progress() (called from stop_wmodules()'s join loop, above)
                // leaves dwCheckPoint/dwWaitHint at whatever it last wrote to signal an
                // in-progress stop; a terminal state has no pending operation left to
                // report, so both must go back to zero here rather than being left stale
                // (issue 38428).
                ossecServiceStatus.dwCurrentState           = SERVICE_STOPPED;
                ossecServiceStatus.dwCheckPoint              = 0;
                ossecServiceStatus.dwWaitHint                = 0;
                SetServiceStatus (ossecServiceStatusHandle, &ossecServiceStatus);
                plain_minfo("Exit completed successfully.");
                break;
        }
    }
}

/* Set the error code in the service */
/* Service DACLs (SDDL). Defaults are what CreateService() gives a service; the protected one keeps
 * SYSTEM's full control and leaves Administrators query, start and interrogate only: no
 * SERVICE_STOP (WP), DELETE (SD), SERVICE_CHANGE_CONFIG (DC), WRITE_DAC (WD) or WRITE_OWNER (WO). */
#define SVC_SDDL_DEFAULT   "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
#define SVC_SDDL_PROTECTED "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
/* The service's registry key: Start=4 would disable it, ImagePath would replace it. Protected: no
 * inheritance, SYSTEM full control, Administrators and Users read only. */
#define SVC_KEY_PATH       "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WazuhSvc"
#define SVC_KEY_PROTECTED  "O:SYD:P(A;CI;KA;;;SY)(A;CI;KR;;;BA)(A;CI;KR;;;BU)"
/* The installation directory: SYSTEM full control, Administrators read and execute, so
 * that ossec.conf (package_uninstallation), client.keys and the binaries cannot be changed,
 * renamed or deleted by an Administrator without first taking ownership back (audited, 4670). */
#define INSTALL_DIR_PROTECTED "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BA)(A;;0x1200a9;;;AU)"
/* What the installer sets (InstallerScripts.vbs): restored when anti-tampering is turned off. */
#define INSTALL_DIR_DEFAULT   "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;AU)"

static int set_service_dacl(const char *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SC_HANDLE scm = NULL, svc = NULL;
    int ret = -1;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, NULL)) {
        merror("Could not build the service security descriptor (%lu).", GetLastError());
        return -1;
    }
    if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT)) &&
            (svc = OpenService(scm, g_lpszServiceName, READ_CONTROL | WRITE_DAC | WRITE_OWNER))) {
        SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
        PSID owner = NULL;
        BOOL owner_defaulted = FALSE;

        if (GetSecurityDescriptorOwner(sd, &owner, &owner_defaulted) && owner) {
            si |= OWNER_SECURITY_INFORMATION;
        }
        if (SetServiceObjectSecurity(svc, si, sd)) {
            ret = 0;
        } else {
            merror("Could not set the security of service '%s' (%lu).", g_lpszServiceName, GetLastError());
        }
    } else {
        merror("Could not open service '%s' to set its security (%lu).", g_lpszServiceName, GetLastError());
    }
    if (svc) {
        CloseServiceHandle(svc);
    }
    if (scm) {
        CloseServiceHandle(scm);
    }
    LocalFree(sd);
    return ret;
}

static int set_service_key_dacl(bool protect)
{
    DWORD rc;

    if (protect) {
        PSECURITY_DESCRIPTOR sd = NULL;
        PACL dacl = NULL;
        PSID owner = NULL;
        BOOL present = FALSE, defaulted = FALSE;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(SVC_KEY_PROTECTED, SDDL_REVISION_1, &sd, NULL) ||
                !GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) ||
                !GetSecurityDescriptorOwner(sd, &owner, &defaulted)) {
            merror("Could not build the service key security descriptor (%lu).", GetLastError());
            LocalFree(sd);
            return -1;
        }
        /* The owner goes back to SYSTEM too: an Administrator who took ownership of the key
         * could otherwise rewrite its DACL. */
        rc = SetNamedSecurityInfoA(SVC_KEY_PATH, SE_REGISTRY_KEY,
                                   OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   owner, NULL, dacl, NULL);
        LocalFree(sd);
    } else {
        /* An empty, unprotected DACL: the key goes back to what it inherits from Services. */
        ACL empty;
        InitializeAcl(&empty, sizeof(empty), ACL_REVISION);
        rc = SetNamedSecurityInfoA(SVC_KEY_PATH, SE_REGISTRY_KEY,
                                   DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                   NULL, NULL, &empty, NULL);
    }
    if (rc != ERROR_SUCCESS) {
        merror("Could not set the security of the service registry key (%lu).", rc);
        return -1;
    }
    return 0;
}

/* Restart the service when its process dies without a stop request (taskkill /f, a crash): the
 * SCM runs these failure actions, and an Administrator cannot remove them without
 * SERVICE_CHANGE_CONFIG, which the protected DACL takes away. */
static int set_service_failure_actions(bool protect)
{
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 5000 }, { SC_ACTION_RESTART, 30000 }
    };
    SERVICE_FAILURE_ACTIONS fa = { 0 };
    SC_HANDLE scm = NULL, svc = NULL;
    int ret = -1;

    if (protect) {
        fa.dwResetPeriod = 86400;
        fa.cActions = 3;
        fa.lpsaActions = actions;
    } else {
        fa.dwResetPeriod = 0;
        fa.cActions = 0;
        fa.lpsaActions = NULL;
    }
    if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT)) &&
            (svc = OpenService(scm, g_lpszServiceName, SERVICE_CHANGE_CONFIG | SERVICE_START))) {
        if (ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
            ret = 0;
        } else {
            merror("Could not set the failure actions of service '%s' (%lu).", g_lpszServiceName, GetLastError());
        }
    } else {
        merror("Could not open service '%s' to set its failure actions (%lu).", g_lpszServiceName, GetLastError());
    }
    if (svc) {
        CloseServiceHandle(svc);
    }
    if (scm) {
        CloseServiceHandle(scm);
    }
    return ret;
}

/* Protect the installation directory (the agent runs from it, so its own path is the one to use).
 * Disabling the protection gives the directory back the ACL it inherits from Program Files. */
static int set_install_dir_acl(bool protect)
{
    char dir[MAX_PATH] = "";
    DWORD len = GetModuleFileNameA(NULL, dir, sizeof(dir));
    char *slash;
    DWORD rc;

    if (len == 0 || len >= sizeof(dir) || !(slash = strrchr(dir, '\\'))) {
        merror("Could not find the installation directory (%lu).", GetLastError());
        return -1;
    }
    *slash = '\0';

    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    PSID owner = NULL;
    BOOL present = FALSE, defaulted = FALSE;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(protect ? INSTALL_DIR_PROTECTED : INSTALL_DIR_DEFAULT,
                                                              SDDL_REVISION_1, &sd, NULL) ||
            !GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) ||
            !GetSecurityDescriptorOwner(sd, &owner, &defaulted)) {
        merror("Could not build the installation directory security descriptor (%lu).", GetLastError());
        LocalFree(sd);
        return -1;
    }
    /* The inheritable ACEs are propagated to everything inside, replacing the inherited ones; the explicit
     * per-file grants the installer manages (Authenticated Users read on non-sensitive files) are kept. */
    rc = SetNamedSecurityInfoA(dir, SE_FILE_OBJECT,
                               OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                               owner, NULL, dacl, NULL);
    LocalFree(sd);
    if (rc != ERROR_SUCCESS) {
        merror("Could not set the security of the installation directory (%lu).", rc);
        return -1;
    }
    return 0;
}

int w_service_tamper_protection(int enable)
{
    int ret = set_service_dacl(enable ? SVC_SDDL_PROTECTED : SVC_SDDL_DEFAULT);

    if (set_service_key_dacl(enable) < 0) {
        ret = -1;
    }
    if (set_service_failure_actions(enable) < 0) {
        ret = -1;
    }
    if (set_install_dir_acl(enable) < 0) {
        ret = -1;
    }
    if (ret == 0) {
        minfo(enable ? "Anti-tampering: service '%s' protected (Administrators cannot stop, delete or reconfigure it, or change the installation directory; it restarts if killed)."
                     : "Anti-tampering: service '%s' permissions restored to the defaults.", g_lpszServiceName);
    }
    return ret;
}

void WinSetError()
{
    OssecServiceCtrlHandler(SERVICE_CONTROL_STOP);
}

/* Initialize the agent service dispatcher */
int os_WinMain(__attribute__((unused)) int argc, __attribute__((unused)) char **argv)
{
    SERVICE_TABLE_ENTRY   steDispatchTable[] = {
        { g_lpszServiceName, OssecServiceStart },
        { NULL,       NULL                     }
    };

    if (!StartServiceCtrlDispatcher(steDispatchTable)) {
        plain_minfo("Unable to set service information.");
        return (1);
    }

    return (1);
}

/* Start OSSEC service */
void WINAPI OssecServiceStart (__attribute__((unused)) DWORD argc, __attribute__((unused)) LPTSTR *argv)
{
#ifdef OSSECHIDS
    /* Must run before RegisterServiceCtrlHandler() below: from that point on,
     * the SCM can invoke OssecServiceCtrlHandler() -> stop_wmodules(), which
     * takes wm_lifecycle_lock (issue 38428). wm_lifecycle_lock_init() is only
     * defined in win_utils.c (win32_common), which this file is also compiled
     * without (win32_service_rk, for the setup/UI tools) -- so this call must
     * stay inside the same OSSECHIDS guard as stop_wmodules()/local_start(). */
    wm_lifecycle_lock_init();
#endif

    ossecServiceStatus.dwServiceType            = SERVICE_WIN32;
    ossecServiceStatus.dwCurrentState           = SERVICE_START_PENDING;
    ossecServiceStatus.dwControlsAccepted       = SERVICE_ACCEPT_STOP;
    ossecServiceStatus.dwWin32ExitCode          = 0;
    ossecServiceStatus.dwServiceSpecificExitCode = 0;
    ossecServiceStatus.dwCheckPoint             = 0;
    ossecServiceStatus.dwWaitHint               = 0;

    ossecServiceStatusHandle =
        RegisterServiceCtrlHandler(g_lpszServiceName,
                                   OssecServiceCtrlHandler);

    if (ossecServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) {
        plain_minfo("RegisterServiceCtrlHandler failed.");
        return;
    }

    ossecServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ossecServiceStatus.dwCheckPoint = 0;
    ossecServiceStatus.dwWaitHint = 0;

    if (!SetServiceStatus(ossecServiceStatusHandle, &ossecServiceStatus)) {
        plain_minfo("SetServiceStatus error.");
        return;
    }

#ifdef OSSECHIDS
    /* Start process */
    local_start();
#endif
}

#endif /* WIN32 */
