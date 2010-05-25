/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: loghandler.h 113 2008-06-25 07:30:25Z tsuruda $
 */

#ifndef __LOGHANDLER_H__
#define __LOGHANDLER_H__

#include <stdbool.h>
#include <syslog.h>

extern void LogHandler_init(void);
extern void LogHandler_cleanup(void);
extern void LogHandler_syslog(int level, const char *format, ...)
    __attribute__ ((format(printf, 2, 3)));
extern bool LogHandler_setPrefix(const char *prefix);
extern const char *LogHandler_getPrefix(void);

#define LogHandler_syslogWithPrefix(priority, format, ...) \
	LogHandler_syslog(priority, "[%s] " format, LogHandler_getPrefix(), ##__VA_ARGS__)

#define LogHandler_syslogWithLineInfo(priority, format, ...) \
	LogHandler_syslog(priority, "[%s] %s: %d %s(): " format, LogHandler_getPrefix(), __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define LogDebug(format, ...) \
	LogHandler_syslogWithLineInfo(LOG_DEBUG, format, ##__VA_ARGS__)

#define LogInfo(format, ...) \
	LogHandler_syslogWithPrefix(LOG_INFO, format, ##__VA_ARGS__)

#define LogNotice(format, ...) \
	LogHandler_syslogWithPrefix(LOG_NOTICE, format, ##__VA_ARGS__)

#define LogWarning(format, ...) \
	LogHandler_syslogWithLineInfo(LOG_WARNING, format, ##__VA_ARGS__)

#define LogError(format, ...) \
	LogHandler_syslogWithLineInfo(LOG_ERR, format, ##__VA_ARGS__)

#define LogEvent(event, format, ...) \
	LogInfo("[" event "] " format, ##__VA_ARGS__)

#define LogNoResource() \
	LogError("memory allocation failed")

#endif /* __LOGHANDLER_H__ */
