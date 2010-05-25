/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfenum.h 49 2008-06-17 00:59:36Z takahiko $
 */

#ifndef __SIDFENUM_H__
#define __SIDFENUM_H__

#include "sidf.h"

extern SidfScore SidfEnum_lookupScoreByKeyword(const char *keyword);
extern const char *SidfEnum_lookupScoreByValue(SidfScore val);

#endif /* __SIDFENUM_H__ */
