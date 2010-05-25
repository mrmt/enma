/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: rcsid.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __RCSID_H__
#define __RCSID_H__

#undef RCSID

#if defined(__GNUC__) && (__GNUC__ > 2)
# define RCSID(x) static const char __attribute__((used)) rcsid[] = x
#else
# define RCSID(x) static const char rcsid[] = x
#endif

#endif /* __RCSID_H__ */
