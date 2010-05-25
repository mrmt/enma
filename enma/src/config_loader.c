/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: config_loader.c 479 2008-08-25 11:46:35Z tsuruda $
 */

#include "rcsid.h"
RCSID("$Id: config_loader.c 479 2008-08-25 11:46:35Z tsuruda $");

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <syslog.h>

#include "ptrop.h"

#include "consolehandler.h"
#include "string_util.h"
#include "syslogtable.h"
#include "config_loader.h"


/**
 * 渡された文字列情報を、文字列のまま設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setString(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    char **config_char_p = (char **) config_storage;

    *config_char_p = strdup(config_value);
    if (NULL == *config_char_p) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return false;
    }
    return true;
}


/**
 * Convert from string to bool
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setBoolean(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    const char true_list[][10] = { "yes", "true", "on", "1" };
    const char false_list[][10] = { "no", "false", "off", "0" };

    int *config_bool_p = (int *) config_storage;

    // true?
    for (int i = 0; i < (int) (sizeof(true_list) / sizeof(true_list[0])); ++i) {
        if (0 == strcasecmp(config_value, true_list[i])) {
            *config_bool_p = true;
            return true;
        }
    }
    // false?
    for (int i = 0; i < (int) (sizeof(false_list) / sizeof(false_list[0])); ++i) {
        if (0 == strcasecmp(config_value, false_list[i])) {
            *config_bool_p = false;
            return true;
        }
    }

    return false;
}


/**
 * 渡された文字列情報を、int に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setInteger(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    if (!isdigits(config_value)) {
        // 形式が数字ではない
        return false;
    }
    int *config_int_p = (int *) config_storage;
    *config_int_p = atoi(config_value);
    return true;
}


/**
 * 渡された文字列情報を、long int に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setLong(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    if (!isdigits(config_value)) {
        // 形式が数字ではない
        return false;
    }
    long int *config_long_p = (long int *) config_storage;
    *config_long_p = atol(config_value);
    return true;
}


/**
 * 渡された文字列情報を、syslogのfacilyを示すint型に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setSyslogFacility(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    int *config_int_p = (int *) config_storage;

    if (-1 == (*config_int_p = lookup_facility_const(config_value))) {;
        return false;
    }

    return true;
}


/**
 * 渡された文字列情報を、syslogのpriorityを示すint型に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setSyslogPriority(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    int *config_int_p = (int *) config_storage;

    if (-1 == (*config_int_p = lookup_priority_const(config_value))) {;
        return false;
    }

    return true;
}


/**
 * 既に設定情報が保持されているかを判定する
 *
 * @param config_storage
 * @param config_type
 * @return
 */
static bool
ConfigLoader_isSet(void *config_storage, const ConfigType config_type)
{
    assert(NULL != config_storage);

    switch (config_type) {
    case CONFIGTYPE_STRING:;
        char **config_char_p = (char **) config_storage;
        if (NULL == *config_char_p) {
            return false;
        }
        break;
    case CONFIGTYPE_BOOLEAN:
    case CONFIGTYPE_INTEGER:
    case CONFIGTYPE_LONG:
    case CONFIGTYPE_SYSLOG_PRIORITY:
    case CONFIGTYPE_SYSLOG_FACILITY:;
        int *config_int_p = (int *) config_storage;
        if (-1 == *config_int_p) {
            return false;
        }
        break;
    default:
        ConsoleError("unknown config type: type=%d", config_type);
        abort();
    }

    return true;
}


/**
 * 各設定情報の型に合わせて設定情報を記憶
 *
 * @param config_entry
 * @param config_struct
 * @param config_value	NULLの場合もある
 * @return
 */
static bool
ConfigLoader_setValue(const ConfigEntry *config_entry, void *config_struct,
                      const char *config_value)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    void *config_storage = STRUCT_MEMBER_P(config_struct, config_entry->struct_offset);

    // 既に保存されていたら上書きしない
    if (ConfigLoader_isSet(config_storage, config_entry->config_type)) {
        return true;
    }

    switch (config_entry->config_type) {
    case CONFIGTYPE_STRING:
        if (NULL != config_value && !ConfigLoader_setString(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_BOOLEAN:
        if (!ConfigLoader_setBoolean(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_INTEGER:
        if (!ConfigLoader_setInteger(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_LONG:
        if (!ConfigLoader_setLong(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_SYSLOG_FACILITY:
        if (!ConfigLoader_setSyslogFacility(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_SYSLOG_PRIORITY:
        if (!ConfigLoader_setSyslogPriority(config_storage, config_value)) {
            return false;
        }
        break;
    default:
        ConsoleError("unknown config type: type=%d", config_entry->config_type);
        abort();
    }
    return true;
}


/**
 * 指定された設定項目に対応するエントリを返す
 *
 * @param config_entry
 * @param entry_name
 * @return
 */
static const ConfigEntry *
ConfigLoader_lookupEntry(const ConfigEntry *config_entry, const char *entry_name)
{
    assert(NULL != config_entry);
    assert(NULL != entry_name);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        if (0 == strncmp(p->config_name, entry_name, strlen(p->config_name))) {
            return p;
        }
    }
    return NULL;
}


/**
 * 指定されたファイルから設定情報を読み込み、記憶する
 *
 * @param config_entry
 * @param filename
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setConfigValue(const ConfigEntry *config_entry, const char *filename,
                            void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != filename);
    assert(NULL != config_struct);

    FILE *fp = fopen(filename, "r");
    if (NULL == fp) {
        ConsoleError("fopen failed: file=%s, error=%s", filename, strerror(errno));
        return false;
    }

    char line[CONFIG_LINE_MAX_LEN];
    char *line_orig;
    int current_line_no = 0;
    char *config_key, *config_value;
    while (NULL != fgets(line, CONFIG_LINE_MAX_LEN, fp)) {
        line_orig = line;
        ++current_line_no;
        (void) strstrip(line);

        // コメント、空行は無視
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        config_key = strtok_r(line, ":", &config_value);
        if (NULL == config_key || NULL == config_value) {
            ConsoleNotice("config parse failed: file=%s:%d, line=%s", filename, current_line_no,
                          line_orig);
            goto error_finally;
        }
        (void) strstrip(config_key);
        (void) strstrip(config_value);

        const ConfigEntry *entry = ConfigLoader_lookupEntry(config_entry, config_key);
        if (NULL == entry) {
            ConsoleNotice("config parse failed: file=%s:%d, key=%s, value=%s", filename,
                          current_line_no, config_key, config_value);
            goto error_finally;
        }
        if (!ConfigLoader_setValue(entry, config_struct, config_value)) {
            ConsoleNotice("config parse failed: file=%s:%d, key=%s, value=%s", filename,
                          current_line_no, config_key, config_value);
            goto error_finally;
        }
    }

    if (0 != ferror(fp)) {
        ConsoleError("fgets failed: file=%s", filename);
        goto error_finally;
    }

    if (0 != fclose(fp)) {
        // エラー出力のみ
        ConsoleError("fclose failed: file=%s, error=%s", filename, strerror(errno));
    }

    return true;

  error_finally:
    if (0 != fclose(fp)) {
        // エラー出力のみ
        ConsoleError("fclose failed: file=%s, error=%s", filename, strerror(errno));
    }
    return false;
}


/**
 * デフォルトの設定情報を設定の保存領域に記憶
 *
 * @param config_entry
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setDefaultValue(const ConfigEntry *config_entry, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        if (!ConfigLoader_setValue(p, config_struct, p->default_value)) {
            // デフォルトの設定値の記憶失敗
            ConsoleNotice("config parse failed: key=%s, value=%s", p->config_name,
                          p->default_value);
            return false;
        }
    }
    return true;
}


/**
 * オプションとして渡された引数の設定情報を保存領域に記憶
 *
 * @param config_entry
 * @param config_key
 * @param config_value
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setOptionValue(const ConfigEntry *config_entry, const char *config_key,
                            const char *config_value, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_key);
    assert(NULL != config_value);
    assert(NULL != config_struct);

    const ConfigEntry *entry = ConfigLoader_lookupEntry(config_entry, config_key);
    if (NULL == entry) {
        ConsoleNotice("config parse failed: key=%s, value=%s", config_key, config_value);
        return false;
    }
    if (!ConfigLoader_setValue(entry, config_struct, config_value)) {
        // 設定値の記憶失敗
        ConsoleNotice("config parse failed: key=%s, value=%s", config_key, config_value);
        return false;
    }

    return true;
}


/**
 * -oオプションで渡された'='付きの設定情報を保存領域に記憶
 *
 * @param config_entry
 * @param optarg
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setEqualStringOptionValue(const ConfigEntry *config_entry, const char *optarg,
                                       void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != optarg);
    assert(NULL != config_struct);

    // key=value を分割
    char *pair = strdup(optarg);
    if (NULL == pair) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return false;
    }
    char *config_key = pair;
    char *config_value = strchr(pair, '=');
    if (NULL != config_value) {
        *config_value++ = '\0';
        // 空白ならエラー
        if (config_value[0] == '\0') {
            goto error_finally;
        }
    } else {
        goto error_finally;
    }

    // key と value を保存
    if (!ConfigLoader_setOptionValue(config_entry, config_key, config_value, config_struct)) {
        goto error_finally;
    }

    PTRINIT(pair);
    return true;

  error_finally:
    PTRINIT(pair);
    return false;
}


/**
 * 設定情報の記憶域の確保
 *
 * @param config_entry
 * @param config_struct
 * @return
 */
void
ConfigLoader_init(const ConfigEntry *config_entry, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        switch (p->config_type) {
        case CONFIGTYPE_STRING:;
            char **config_char_p = (char **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            *config_char_p = NULL;
            break;
        case CONFIGTYPE_BOOLEAN:
        case CONFIGTYPE_INTEGER:
        case CONFIGTYPE_LONG:
        case CONFIGTYPE_SYSLOG_FACILITY:
        case CONFIGTYPE_SYSLOG_PRIORITY:;
            int *config_int_p = (int *) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            *config_int_p = -1;
            break;
        default:
            ConsoleError("unknown config type: type=%d", p->config_type);
            abort();
        }
    }
}


/**
 * 設定情報の記憶領域を解放
 *
 * @param config_entry
 * @param config_struct
 * @return
 */
void
ConfigLoader_free(const ConfigEntry *config_entry, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        switch (p->config_type) {
        case CONFIGTYPE_STRING:;
            char **config_char_p = (char **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            PTRINIT(*config_char_p);
            break;
        case CONFIGTYPE_BOOLEAN:
        case CONFIGTYPE_INTEGER:
        case CONFIGTYPE_LONG:
        case CONFIGTYPE_SYSLOG_FACILITY:
        case CONFIGTYPE_SYSLOG_PRIORITY:
            break;
        default:
            ConsoleError("unknown config type: type=%d", p->config_type);
            abort();
        }
    }
}


/**
 * 現在の設定情報を表示する
 *
 * @param config_entry
 * @param config_struct
 * @param out
 */
void
ConfigLoader_dump(const ConfigEntry *config_entry, const void *config_struct, FILE *out)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);
    assert(NULL != out);

    fprintf(out, "configure list:\n");
    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        fprintf(out, "  %s: ", p->config_name);
        void *value = STRUCT_MEMBER_P(config_struct, p->struct_offset);

        switch (p->config_type) {
        case CONFIGTYPE_STRING:
            fprintf(out, "%s", NNSTR(*(char **) value));
            break;
        case CONFIGTYPE_BOOLEAN:
            fprintf(out, "%s", *(int *) value ? "true" : "false");
            break;
        case CONFIGTYPE_INTEGER:
            fprintf(out, "%d", *(int *) value);
            break;
        case CONFIGTYPE_LONG:
            fprintf(out, "%ld", *(long *) value);
            break;
        case CONFIGTYPE_SYSLOG_FACILITY:
            fprintf(out, "%s", lookup_facility_name(*(int *) value));
            break;
        case CONFIGTYPE_SYSLOG_PRIORITY:
            fprintf(out, "%s", lookup_priority_name(*(int *) value));
            break;
        default:
            ConsoleError("unknown config type: type=%d", p->config_type);
            abort();
        }
        fprintf(out, "\n");
    }
    fflush(out);
}
