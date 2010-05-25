/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: daemonize.h 139 2008-06-27 08:55:53Z tsuruda $
 */

#ifndef __DAEMONIZE_H__
#define __DAEMONIZE_H__

#include <stdbool.h>

bool daemonize_init(const char *username, const char *chdirpath, const char *pidfile,
                    int argc, char **argv);
bool daemonize_finally(const char *pidfile);

#endif
