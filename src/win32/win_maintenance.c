/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Anti-tampering maintenance window (Windows).
 *
 * With anti_tampering/package_uninstallation enabled, w_service_tamper_protection() leaves
 * Administrators unable to stop, reconfigure or remove the agent. An Administrator who has the
 * manager's permission (the same agent:uninstall check the uninstallation uses) can lift that for
 * a limited time:
 *
 *   wazuh-agent.exe --maintenance --uninstall-auth-host <host:port> --uninstall-auth-token <token>
 *
 * The command only forwards the request to the running service over a local named pipe that only
 * SYSTEM and Administrators can open. The service, running as SYSTEM, asks the manager itself, so
 * the outcome cannot be faked by the caller. If the manager grants it, the protection is removed
 * for 30 minutes by default, or until the service restarts, whichever comes first. Every
 * request is logged and written to the Windows Application log, which the agent collects by
 * default, so the manager sees who asked and what it answered. */

#ifdef WIN32

#include "shared.h"
#include "os_win.h"
#include "agentd.h"
#include <sddl.h>

#define MAINTENANCE_PIPE        "\\\\.\\pipe\\wazuh-agent-maintenance"
/* Only SYSTEM and Administrators: other users cannot even connect. */
#define MAINTENANCE_PIPE_SDDL   "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)"
/* Length of the window, agent.anti_tampering_maintenance_window in local_internal_options.conf (seconds).
 * That file is in the protected installation directory, so it cannot be raised without a window. */
#define MAINTENANCE_WINDOW_DEFAULT_S 1800
#define MAINTENANCE_REQ_MAX     4096
#define MAINTENANCE_DENY_DELAY  3000
#define MAINTENANCE_EVENT_ID    1000

/* End of the current window (0: none). Guarded by maintenance_lock. */
static time_t maintenance_until;
static int maintenance_window_s = MAINTENANCE_WINDOW_DEFAULT_S;
static CRITICAL_SECTION maintenance_lock;

/* Copy to the Windows Application log, collected by the agent's default configuration. */
static void maintenance_event(WORD type, const char *message)
{
    HANDLE source = RegisterEventSourceA(NULL, "Wazuh");

    if (source) {
        LPCSTR strings[1] = { message };
        ReportEventA(source, type, 0, MAINTENANCE_EVENT_ID, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(source);
    }
}

static void maintenance_reply(HANDLE pipe, const char *reply)
{
    DWORD written = 0;
    WriteFile(pipe, reply, (DWORD)strlen(reply), &written, NULL);
}

/* "key=value" lines; values point into req. */
static const char *maintenance_field(char *line, const char *key)
{
    size_t len = strlen(key);

    if (strncmp(line, key, len) == 0 && line[len] == '=') {
        return line + len + 1;
    }
    return NULL;
}

static void maintenance_handle(HANDLE pipe)
{
    char req[MAINTENANCE_REQ_MAX + 1];
    char user[257] = "unknown";
    char message[OS_SIZE_1024];
    DWORD user_len = sizeof(user);
    DWORD n = 0;
    const char *host = NULL;
    const char *token = NULL;
    const char *login = NULL;
    bool ssl_verify = true;
    char *save = NULL;
    char *line;

    if (!ReadFile(pipe, req, MAINTENANCE_REQ_MAX, &n, NULL)) {
        maintenance_reply(pipe, "ERROR request too long or unreadable");
        return;
    }
    req[n] = '\0';

    /* Who is asking, for the log. */
    if (ImpersonateNamedPipeClient(pipe)) {
        if (!GetUserNameA(user, &user_len)) {
            snprintf(user, sizeof(user), "unknown");
        }
        if (!RevertToSelf()) {
            merror_exit("Anti-tampering: could not revert the maintenance pipe impersonation (%lu).", GetLastError());
        }
    }

    for (line = strtok_r(req, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        const char *v;

        if ((v = maintenance_field(line, "host")) && *v) {
            host = v;
        } else if ((v = maintenance_field(line, "token")) && *v) {
            token = v;
        } else if ((v = maintenance_field(line, "login")) && *v) {
            login = v;
        } else if ((v = maintenance_field(line, "ssl"))) {
            ssl_verify = strcmp(v, "0") != 0;
        }
    }

    if (!host || (!token && !login)) {
        SecureZeroMemory(req, sizeof(req));
        maintenance_reply(pipe, "ERROR missing host and token or login");
        return;
    }

    minfo("Anti-tampering: maintenance requested by '%s', asking the manager.", user);

    /* package_uninstall_validation() returns false when the manager grants the permission. */
    bool denied = package_uninstall_validation(token, login, host, ssl_verify);
    SecureZeroMemory(req, sizeof(req));

    if (denied) {
        snprintf(message, sizeof(message),
                 "Anti-tampering: maintenance request by '%s' not authorized by the manager.", user);
        mwarn("%s", message);
        maintenance_event(EVENTLOG_WARNING_TYPE, message);
        /* Slow down guessing through this channel. */
        Sleep(MAINTENANCE_DENY_DELAY);
        maintenance_reply(pipe, "DENIED");
        return;
    }

    EnterCriticalSection(&maintenance_lock);
    int ret = w_service_tamper_protection(0);
    if (ret == 0) {
        maintenance_until = time(NULL) + maintenance_window_s;
    }
    LeaveCriticalSection(&maintenance_lock);

    if (ret != 0) {
        maintenance_reply(pipe, "ERROR the protection could not be removed, see ossec.log");
        return;
    }

    snprintf(message, sizeof(message),
             "Anti-tampering: protection suspended for %d seconds for maintenance, authorized by the manager (requested by '%s').",
             maintenance_window_s, user);
    mwarn("%s", message);
    maintenance_event(EVENTLOG_WARNING_TYPE, message);

    snprintf(message, sizeof(message), "OK %d", maintenance_window_s);
    maintenance_reply(pipe, message);
}

static DWORD WINAPI maintenance_server(__attribute__((unused)) LPVOID arg)
{
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(MAINTENANCE_PIPE_SDDL, SDDL_REVISION_1,
                                                              &sa.lpSecurityDescriptor, NULL)) {
        merror("Anti-tampering: could not build the maintenance pipe security descriptor (%lu).", GetLastError());
        return 1;
    }

    for (;;) {
        /* FILE_FLAG_FIRST_PIPE_INSTANCE: fail rather than share the name with a pipe someone else
         * created first. */
        HANDLE pipe = CreateNamedPipeA(MAINTENANCE_PIPE,
                                       PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                       1, MAINTENANCE_REQ_MAX, MAINTENANCE_REQ_MAX, 0, &sa);

        if (pipe == INVALID_HANDLE_VALUE) {
            merror("Anti-tampering: could not create the maintenance pipe (%lu).", GetLastError());
            Sleep(60000);
            continue;
        }
        if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            maintenance_handle(pipe);
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    return 0;
}

/* Puts the protection back when the window is over. */
static DWORD WINAPI maintenance_expiry(__attribute__((unused)) LPVOID arg)
{
    for (;;) {
        Sleep(15000);

        EnterCriticalSection(&maintenance_lock);
        if (maintenance_until != 0 && time(NULL) >= maintenance_until) {
            /* On failure the window stays open and this is tried again on the next round. */
            if (w_service_tamper_protection(1) == 0) {
                const char *message = "Anti-tampering: maintenance window over, protection restored.";
                maintenance_until = 0;
                minfo("%s", message);
                maintenance_event(EVENTLOG_INFORMATION_TYPE, message);
            }
        }
        LeaveCriticalSection(&maintenance_lock);
    }
    return 0;
}

void w_maintenance_start(void)
{
    InitializeCriticalSection(&maintenance_lock);
    maintenance_window_s = getDefine_Int_default("agent", "anti_tampering_maintenance_window", 60, 86400,
                                                 MAINTENANCE_WINDOW_DEFAULT_S);

    HANDLE server = CreateThread(NULL, 0, maintenance_server, NULL, 0, NULL);
    HANDLE expiry = CreateThread(NULL, 0, maintenance_expiry, NULL, 0, NULL);

    if (!server || !expiry) {
        merror("Anti-tampering: could not start the maintenance threads (%lu).", GetLastError());
    }
    if (server) {
        CloseHandle(server);
    }
    if (expiry) {
        CloseHandle(expiry);
    }
}

int w_maintenance_cli(int argc, char **argv)
{
    const char *token = NULL;
    const char *login = NULL;
    const char *host = NULL;
    bool ssl_verify = true;
    char req[MAINTENANCE_REQ_MAX];
    char reply[256] = "";
    DWORD n = 0;
    int len;

    /* argv[1] is --maintenance. */
    if (w_uninstall_parse_args(argc, argv, 2, &token, &login, &host, &ssl_verify) != 0) {
        return 1;
    }

    len = snprintf(req, sizeof(req), "host=%s\ntoken=%s\nlogin=%s\nssl=%d\n",
                   host, token ? token : "", login ? login : "", ssl_verify ? 1 : 0);
    if (len < 0 || len >= (int)sizeof(req)) {
        printf("The request is too long.\n");
        return 1;
    }

    BOOL ok = CallNamedPipeA(MAINTENANCE_PIPE, req, (DWORD)len, reply, sizeof(reply) - 1, &n, 10000);
    DWORD err = GetLastError();
    SecureZeroMemory(req, sizeof(req));

    if (!ok) {
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_SEM_TIMEOUT) {
            printf("The agent is not running with anti-tampering enabled, or it is busy (%lu).\n", err);
        } else {
            printf("Could not reach the agent (%lu).\n", err);
        }
        return 1;
    }
    reply[n] = '\0';

    if (strncmp(reply, "OK ", 3) == 0) {
        printf("Authorized by the manager: anti-tampering is suspended for %s seconds, or until the agent restarts.\n", reply + 3);
        return 0;
    }
    if (strcmp(reply, "DENIED") == 0) {
        printf("Not authorized by the manager.\n");
        return 1;
    }
    printf("%s\n", reply);
    return 1;
}

#endif /* WIN32 */
