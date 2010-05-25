/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id:enma_config.h 154 2008-07-07 08:16:11Z tsuruda $
 */

#ifndef __ENMA_CONFIG_H__
#define __ENMA_CONFIG_H__

#include <sys/types.h>
#include <assert.h>
#include <stdbool.h>

// 設定情報の記憶領域
typedef struct EnmaConfig {
    // milter
    int milter_verbose;         //boolean
    char *milter_conffile;
    char *milter_socket;
    const char *milter_user;
    const char *milter_pidfile;
    const char *milter_chdir;
    int milter_timeout;
    int milter_loglevel;
    int milter_postfix;         //boolean
    // syslog
    const char *syslog_ident;
    int syslog_facility;
    int syslog_logmask;
    // authresult
    int spf_auth;               //boolean
    int spf_explog;             //boolean
    int sidf_auth;              //boolean
    int sidf_explog;            //boolean
    const char *authresult_identifier;
} EnmaConfig;

extern bool EnmaConfig_setConfig(EnmaConfig *self, int argc, char **argv);
extern EnmaConfig *EnmaConfig_new(void);
extern void EnmaConfig_free(EnmaConfig *self);

#endif
