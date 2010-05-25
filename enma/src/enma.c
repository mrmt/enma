/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma.c 160 2008-07-07 08:33:00Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma.c 160 2008-07-07 08:33:00Z takahiko $");

#include <stdio.h>
#include <assert.h>
#include <sysexits.h>
#include <stdlib.h>
#include <syslog.h>

#include <libmilter/mfapi.h>

#include "loghandler.h"
#include "sidfpolicy.h"

#include "consolehandler.h"
#include "enma_config.h"
#include "enma_mfi.h"
#include "daemonize.h"
#include "enma.h"


// グローバル変数を定義
SidfPolicy *g_sidf_policy = NULL;   // sidfのポリシーオブジェクトの記憶
EnmaConfig *g_enma_config = NULL;   // enmaの設定情報を記憶


/**
 * enmaの起動方法の説明を表示する
 * 
 * @param out
 */
static void
enma_usage(FILE *out)
{
    fprintf(out, "Usage:\n");
    fprintf(out, "\tenma [options] [conffile]\n");
    fflush(out);
}


/**
 * 設定情報の初期化
 * 
 * @param argc
 * @param argv
 * @return
 */
static int
config_init(int argc, char **argv)
{
    g_enma_config = EnmaConfig_new();
    if (NULL == g_enma_config) {
        return EX_OSERR;
    }

    if (!EnmaConfig_setConfig(g_enma_config, argc, argv)) {
        EnmaConfig_free(g_enma_config);
        enma_usage(stderr);
        return EX_USAGE;
    }

    return 0;
}


/**
 * sidfで利用する情報の初期化
 * 
 * @return
 */
static int
sidf_init(void)
{
    g_sidf_policy = SidfPolicy_new();
    if (NULL == g_sidf_policy) {
        return EX_OSERR;
    }
    g_sidf_policy->lookup_spf_rr = false;
    g_sidf_policy->lookup_exp = false;

    if (SIDF_STAT_OK !=
        SidfPolicy_setCheckingDomain(g_sidf_policy, g_enma_config->authresult_identifier)) {
        return EX_OSERR;
    }

    return 0;
}


/**
 * メイン
 * 
 * @param argc
 * @param argv
 * @return
 */
int
main(int argc, char **argv)
{
    int result = 0;
    // 設定情報の読み込み
    if (0 != (result = config_init(argc, argv))) {
        ConsoleError("enma starting up failed: error=config_init failed");
        exit(result);
    }
    // ログ出力のための初期化
    openlog(g_enma_config->syslog_ident, LOG_PID | LOG_NDELAY, g_enma_config->syslog_facility);
    setlogmask(LOG_UPTO(g_enma_config->syslog_logmask));
    LogHandler_init();

    // ポリシーを初期化 
    if (0 != (result = sidf_init())) {
        ConsoleError("enma starting up failed: error=sidf_init failed");
        exit(result);
    }
    // milterを初期化
    if (!EnmaMfi_init
        (g_enma_config->milter_socket, g_enma_config->milter_timeout,
         g_enma_config->milter_loglevel)) {
        ConsoleError("enma starting up failed: error=EnmaMfi_init failed");
        exit(EX_OSERR);
    }
    // daemonize
    if (!daemonize_init
        (g_enma_config->milter_user, g_enma_config->milter_chdir, g_enma_config->milter_pidfile,
         argc, argv)) {
        ConsoleError("enma starting up failed: error=daemonize_init failed");
        LogError("enma starting up failed: error=daemonize_init failed");
        exit(EX_OSERR);
    }

    LogInfo("enma starting up");
    int smfi_return_val = smfi_main();
    LogInfo("enma shutting down: result=%d", smfi_return_val);

    if (!daemonize_finally(g_enma_config->milter_pidfile)) {
        LogError("daemonize_finally failed");
        exit(EX_OSERR);
    }

    SidfPolicy_free(g_sidf_policy);
    EnmaConfig_free(g_enma_config);

    LogHandler_cleanup();
    closelog();

    return smfi_return_val;
}
