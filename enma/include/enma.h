/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma.h 218 2008-07-18 04:58:52Z tsuruda $
 */

#ifndef __ENMA_H__
#define __ENMA_H__

#include "enma_config.h"
#include "sidfpolicy.h"

#define ENMA_MILTER_NAME "enma"

extern EnmaConfig *g_enma_config;
extern SidfPolicy *g_sidf_policy;

#endif
