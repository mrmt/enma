/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: syslogtable.h 138 2008-06-27 08:45:18Z tsuruda $
 */

#ifndef __SYSLOGTABLE_H__
#define __SYSLOGTABLE_H__

int lookup_facility_const(const char *facility_name);
const char *lookup_facility_name(const int facility_const);
int lookup_priority_const(const char *priority_name);
const char *lookup_priority_name(const int priority_name);

#endif
