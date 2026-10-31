#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"

/* The binaries are GUI subsystem executables: there is no console, and every
 * LOG_* call can only ever reach the log file (which exists only when
 * --log-file was given). Nothing here writes to stdout/stderr any more. */

static FILE *log_file = NULL;
static CRITICAL_SECTION log_lock;
static BOOL logger_initialized = FALSE;

BOOL logger_init(const wchar_t *log_path) {
    if (logger_initialized) {
        return TRUE;
    }

    InitializeCriticalSection(&log_lock);

    /* binary mode on purpose: lines are written as explicit UTF-8 bytes below,
     * so non-ASCII paths never depend on the CRT locale or a console code page */
    log_file = _wfopen(log_path, L"wb");
    if (!log_file) {
        DeleteCriticalSection(&log_lock);
        return FALSE;
    }

    logger_initialized = TRUE;
    return TRUE;
}

void logger_cleanup(void) {
    if (!logger_initialized) {
        return;
    }

    EnterCriticalSection(&log_lock);

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }

    LeaveCriticalSection(&log_lock);
    DeleteCriticalSection(&log_lock);

    logger_initialized = FALSE;
}

BOOL logger_is_active(void) {
    return logger_initialized && log_file != NULL;
}

void logger_log(LogLevel level, const wchar_t *format, ...) {
    if (!logger_is_active()) {
        return;
    }

    const wchar_t *level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = L"DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = L"INFO "; break;
        case LOG_LEVEL_WARN:  level_str = L"WARN "; break;
        case LOG_LEVEL_ERROR: level_str = L"ERROR"; break;
        default:              level_str = L"?????"; break;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t timestamp[32];
    swprintf(timestamp, 32, L"%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);

    wchar_t message[2048];
    va_list args;
    va_start(args, format);
    _vsnwprintf(message, 2048, format, args);
    message[2047] = L'\0';
    va_end(args);

    wchar_t log_line[2560];
    _snwprintf(log_line, 2560, L"[%ls] [%ls] %ls\n", timestamp, level_str, message);
    log_line[2559] = L'\0';

    int needed = WideCharToMultiByte(CP_UTF8, 0, log_line, -1, NULL, 0, NULL, NULL);
    if (needed <= 1) {
        return;
    }

    char *utf8 = (char *)malloc((size_t)needed);
    if (!utf8) {
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, log_line, -1, utf8, needed, NULL, NULL);

    EnterCriticalSection(&log_lock);
    if (log_file) {
        fwrite(utf8, 1, (size_t)needed - 1, log_file);
        fflush(log_file);
    }
    LeaveCriticalSection(&log_lock);

    free(utf8);
}
