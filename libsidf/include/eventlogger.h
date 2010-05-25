/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: eventlogger.h 52 2008-06-17 01:29:51Z takahiko $
 */

#ifndef __EVENTLOGGER_H__
#define __EVENTLOGGER_H__

#include "loghandler.h"

#define LogImplError(format, ...) \
	LogError(format, ##__VA_ARGS__)

#define LogSysError(format, ...) \
	LogError(format, ##__VA_ARGS__)

#define LogConfigError(format, ...) \
	LogError(format, ##__VA_ARGS__)

#define LogPermFail(format, ...) \
	LogInfo(format, ##__VA_ARGS__)

#define LogDnsError(format, ...) \
	LogInfo(format, ##__VA_ARGS__)

#define LogSidfNotice(format, ...) \
    LogInfo(format, ##__VA_ARGS__)

#define LogSidfDebug(format, ...) \
	LogDebug(format, ##__VA_ARGS__)

#define LogSidfParseTrace(format, ...)

#endif /* __EVENTLOGGER_H__ */
