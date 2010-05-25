/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: posixaux.h 152 2008-07-07 05:49:29Z tsuruda $
 */

#ifndef __POSIXAUX_H__
#define __POSIXAUX_H__

#include <errno.h>

#ifndef SKIP_EINTR
#define SKIP_EINTR(expr) do {} while (-1 == (expr) && EINTR == errno)
#endif

#ifndef EOK
#define EOK 0   /* no error */
#endif

#endif /*__POSIXAUX_H__*/
