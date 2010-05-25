/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: bitmemcmp.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __BITMEMCMP_H__
#define __BITMEMCMP_H__

#include <sys/types.h>

extern int bitmemcmp(const void *s1, const void *s2, size_t bits);

#endif /* __BITMEMCMP_H__ */
