/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: inet_ppton.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __INET_PPTON_H__
#define __INET_PPTON_H__

int inet_ppton(int af, const char *src, const char *src_tail, void *dst);

#endif /* __INET_PPTON_H__ */
