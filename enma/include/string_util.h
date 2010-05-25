/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: string_util.h 91 2008-06-23 07:38:37Z tsuruda $
 */

#ifndef __STRING_UTIL_H__
#define __STRING_UTIL_H__

#include <stdbool.h>

extern bool isdigits(const char *string);
extern char *strlstrip(char *string);
extern char *strrstrip(char *string);
extern char *strstrip(char *string);

#endif
