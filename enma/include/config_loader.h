/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: config_loader.h 302 2008-08-07 14:33:37Z tsuruda $
 */

#ifndef __CONFIG_LOADER_H__
#define __CONFIG_LOADER_H__

#include <stdbool.h>

typedef enum {
    CONFIGTYPE_STRING,
    CONFIGTYPE_BOOLEAN,
    CONFIGTYPE_INTEGER,
    CONFIGTYPE_LONG,
    CONFIGTYPE_SYSLOG_PRIORITY,
    CONFIGTYPE_SYSLOG_FACILITY,
} ConfigType;

typedef struct ConfigEntry {
    const char *config_name;    // 設定項目の名前
    const ConfigType config_type;   // 設定項目の型 
    const char *default_value;  // 設定項目のデフォルト値
    const int struct_offset;    // 構造体の変数へのオフセット
    const char *description;    // 設定項目の説明文
} ConfigEntry;

#define CONFIG_LINE_MAX_LEN 512 // configファイルの一行の最大長

extern bool ConfigLoader_setConfigValue(const ConfigEntry *config_entry, const char *filename,
                                        void *config_struct);
extern bool ConfigLoader_setDefaultValue(const ConfigEntry *config_entry, void *config_struct);
extern bool ConfigLoader_setEqualStringOptionValue(const ConfigEntry *config_entry,
                                                   const char *optarg, void *config_struct);
extern bool ConfigLoader_setOptionValue(const ConfigEntry *config_entry, const char *config_key,
                                        const char *config_value, void *config_struct);
extern void ConfigLoader_init(const ConfigEntry *config_entry, void *config_struct);
extern void ConfigLoader_free(const ConfigEntry *config_entry, void *config_struct);
extern void ConfigLoader_dump(const ConfigEntry *config_entry, const void *config_struct,
                              FILE *out);

#endif
