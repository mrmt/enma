/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: consolehandler.h 113 2008-06-25 07:30:25Z tsuruda $
 */

#ifndef __CONSOLEHANDLER_H__
#define __CONSOLEHANDLER_H__

#include <stdio.h>

#define ConsoleInfo(format, ...) \
	fprintf(stdout, format "\n", ##__VA_ARGS__)

#define ConsoleNotice(format, ...) \
	fprintf(stderr, format "\n", ##__VA_ARGS__)

#define ConsoleError(format, ...) \
	fprintf(stderr, "%s: %d %s(): " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#endif
