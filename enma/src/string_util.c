/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: string_util.c 114 2008-06-25 07:31:01Z tsuruda $
 */

#include "rcsid.h"
RCSID("$Id: string_util.c 114 2008-06-25 07:31:01Z tsuruda $");

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "string_util.h"

/**
 * 文字列が全て正の整数であるかをチェック
 * 　負の数、小数は false になる
 * 
 * @param string    検査文字列
 * @return  整数ならばtrue、そうでなければflase
 */
bool
isdigits(const char *string)
{
    assert(NULL != string);

    for (const char *p = string; *p != '\0'; ++p) {
        if (!isdigit((int) (*p))) {
            return false;
        }
    }

    return true;
}


/**
 * 前方の空白を取り除く
 * 
 * @param string	処理対象の文字列
 * @return	前方の空白を取り除いた文字列へのポインタ
 */
char *
strlstrip(char *string)
{
    assert(NULL != string);

    char *start = string;
    // 空白をスキップ
    for (; *start != '\0' && isspace((int) (*start)); ++start);
    memmove(string, start, strlen(start) + 1);

    return string;
}


/**
 * 後方の空白を取り除く
 * 
 * @param string	処理対象の文字列
 * @return	後方の空白を取り除いた文字列へのポインタ
 */
char *
strrstrip(char *string)
{
    assert(NULL != string);

    char *end = string + strlen(string) - 1;

    for (; string <= end && isspace((int) (*end)); --end);
    *(end + 1) = '\0';

    return string;
}


/**
 * 前後の空白を取り除く
 * 
 * @param string	処理対象の文字列
 * @return	前後の空白を取り除いた文字列へのポインタ
 */
char *
strstrip(char *string)
{
    assert(NULL != string);

    return strlstrip(strrstrip(string));
}
