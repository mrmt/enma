/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id:enma_config.c 154 2008-07-07 08:16:11Z tsuruda $
 */

#include "rcsid.h"
RCSID("$Id:enma_config.c 154 2008-07-07 08:16:11Z tsuruda $");

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#include "ptrop.h"

#include "consolehandler.h"
#include "config_loader.h"
#include "enma.h"
#include "enma_config.h"

// *INDENT-OFF*

static ConfigEntry ConfigEntry_table[] = {
    {"milter.verbose", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, milter_verbose),
        "verbose mode. same option as '-v' (true or false)"},
    {"milter.conffile", CONFIGTYPE_STRING, NULL, offsetof(EnmaConfig, milter_conffile),
        "configuration file on startup. same option as '-c filename' (filename)"},
    // libmilter
    {"milter.user", CONFIGTYPE_STRING, NULL, offsetof(EnmaConfig, milter_user),
        "user/group id of daemon startup (username)"},
    {"milter.pidfile", CONFIGTYPE_STRING, "/var/run/" ENMA_MILTER_NAME "/" ENMA_MILTER_NAME ".pid", offsetof(EnmaConfig, milter_pidfile),
        "path to pid file (filename)"},
    {"milter.chdir", CONFIGTYPE_STRING, "/var/tmp/", offsetof(EnmaConfig, milter_chdir),
        "change working directory (dirname)"},
    {"milter.socket", CONFIGTYPE_STRING, "inet:10025@127.0.0.1", offsetof(EnmaConfig, milter_socket),
        "address of milter socket"},
    {"milter.timeout", CONFIGTYPE_INTEGER, "7210", offsetof(EnmaConfig, milter_timeout),
        "I/O timeout (seconds)"},
    {"milter.loglevel", CONFIGTYPE_INTEGER, "0", offsetof(EnmaConfig, milter_loglevel),
        "log level of libmilter (integer)"},
    {"milter.postfix", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, milter_postfix),
        "use postfix's milter (true or false)"},
    // syslog
    {"syslog.ident", CONFIGTYPE_STRING, ENMA_MILTER_NAME, offsetof(EnmaConfig, syslog_ident),
        "syslog identifier"},
    {"syslog.facility", CONFIGTYPE_SYSLOG_FACILITY, "local4", offsetof(EnmaConfig, syslog_facility),
        "specify the type of daemon"},
    {"syslog.logmask", CONFIGTYPE_SYSLOG_PRIORITY, "info", offsetof(EnmaConfig, syslog_logmask),
        "syslog priority mask"},
    // spf
    {"spf.auth", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, spf_auth),
        "enable SPF authentication (true or false)"},
    {"spf.explog", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, spf_explog),
        "record explanation of SPF (true or false)"},
    // sidf
    {"sidf.auth", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, sidf_auth),
        "enalbe SIDF authentication (true or false)"},
    {"sidf.explog", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, sidf_explog),
        "record the explanation of SIDF (true or false)"},
    // authresult
    {"authresult.identifier", CONFIGTYPE_STRING, "localhost", offsetof(EnmaConfig, authresult_identifier),
        "identifier of Authentication-Results header"},
    {NULL, 0, NULL, 0, NULL}
};

// *INDENT-ON*


/**
 * configの説明を表示する
 *
 * @param out	出力先のストリーム
 */
static void
EnmaConfig_usage(FILE *out)
{
    assert(NULL != out);

    fprintf(out, "Options[with default]:\n");
    fprintf(out, "  -h\t: show this message\n");
    fprintf(out, "  -v\t: verbose mode\n");
    fprintf(out, "  -c filename\t: configuration file on startup\n");
    fprintf(out, "\n");
    for (const ConfigEntry *p = ConfigEntry_table; NULL != p->config_name; ++p) {
        fprintf(out, "  -o %s\t: %s [%s]\n", p->config_name, p->description,
                NNSTR(p->default_value));
    }
    fflush(out);
}


/**
 * 引数で渡された設定情報を設定の保存領域に記憶
 *
 * @param self
 * @param argc
 * @param argv
 * @return
 */
static bool
EnmaConfig_getopt(EnmaConfig *self, int argc, char **argv)
{
    assert(NULL != self);
    assert(0 < argc);
    assert(NULL != argv);

    int c;
    while (-1 != (c = getopt(argc, argv, "o:c:vh"))) {
        switch (c) {
        case 'o':
            if (!ConfigLoader_setEqualStringOptionValue(ConfigEntry_table, optarg, self)) {
                return false;
            }
            break;
        case 'c':
            if (!ConfigLoader_setOptionValue(ConfigEntry_table, "milter.conffile", optarg, self)) {
                return false;
            }
            break;
        case 'v':
            if (!ConfigLoader_setOptionValue(ConfigEntry_table, "milter.verbose", "true", self)) {
                return false;
            }
            break;
        case 'h':
            EnmaConfig_usage(stderr);
            exit(EX_USAGE);
        default:
            EnmaConfig_usage(stderr);
            exit(EX_USAGE);
        }
    }

    return true;
}


/**
 * 設定情報を記憶する
 *
 * @param self
 * @param argc
 * @param argv
 * @return
 */
bool
EnmaConfig_setConfig(EnmaConfig *self, int argc, char **argv)
{
    assert(NULL != self);
    assert(0 < argc);
    assert(NULL != argv);

    // 引数を元に設定情報を記憶
    if (!EnmaConfig_getopt(self, argc, argv)) {
        ConsoleNotice("config getopt value set failed");
        return false;
    }
    // 余計な引数がないかチェック
    argc -= optind;
    argv += optind;
    if (0 < argc) {
        ConsoleNotice("too many arguments.");
        return false;
    }
    // 設定ファイルを元に設定情報を記憶
    if (NULL != g_enma_config->milter_conffile) {
        if (!ConfigLoader_setConfigValue(ConfigEntry_table, g_enma_config->milter_conffile, self)) {
            ConsoleNotice("config file load faild");
            return false;
        }
    }
    // デフォルト値を記憶
    if (!ConfigLoader_setDefaultValue(ConfigEntry_table, self)) {
        ConsoleNotice("config default value set failed");
        return false;
    }

    if (self->milter_verbose) {
        ConfigLoader_dump(ConfigEntry_table, self, stderr);
    }
    return true;
}


/**
 * EnmaConfig オブジェクトの構築
 *
 * @return 各設定情報を記憶した EnmaConfig オブジェクト
 */
EnmaConfig *
EnmaConfig_new(void)
{
    EnmaConfig *self = (EnmaConfig *) malloc(sizeof(EnmaConfig));
    if (NULL == self) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return NULL;
    }
    // 初期化するのみ
    ConfigLoader_init(ConfigEntry_table, self);

    return self;
}


/**
 * EnmaConfig オブジェクトの解放
 *
 * @param self 解放する EnmaConfig オブジェクト
 */
void
EnmaConfig_free(EnmaConfig *self)
{
    assert(NULL != self);

    // 解放するのみ
    ConfigLoader_free(ConfigEntry_table, self);
    free(self);
}
