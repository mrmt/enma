/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: strarray.c 49 2008-06-17 00:59:36Z takahiko $
 */
/**
 * @file
 * @brief 文字列を格納する可変長配列
 * @version $Id: strarray.c 49 2008-06-17 00:59:36Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: strarray.c 49 2008-06-17 00:59:36Z takahiko $");

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "ptrarray.h"
#include "strarray.h"

/**
 * StrArray オブジェクトの構築
 * @return 空の StrArray オブジェクト
 */
StrArray *
StrArray_new(size_t size)
{
    return PtrArray_new(size, free);
}   // end function : StrArray_new

/**
 * StrArray オブジェクトに格納している文字列への参照を取得する
 * @param self StrArray オブジェクト
 * @param pos 要素の番号
 * @return 文字列への参照
 */
const char *
StrArray_get(const StrArray *self, size_t pos)
{
    return (const char *) PtrArray_get(self, pos);
}   // end function : StrArray_get

/**
 * StrArray オブジェクトに文字列を格納する
 * @param self StrArray オブジェクト
 * @param pos 要素の番号
 * @param val 格納する文字列
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_set(StrArray *self, size_t pos, const char *val)
{
    char *buf = strdup(val);
    if (NULL == buf) {
        return -1;
    }   // end if
    int ret = PtrArray_set(self, pos, buf);
    if (0 > ret) {
        free(buf);
    }   // end if
    return ret;
}   // end function : StrArray_set

/**
 * StrArray オブジェクトに文字列を格納する
 * @param self StrArray オブジェクト
 * @param pos 要素の番号
 * @param val 格納する文字列
 * @param len 格納する文字列のサイズ
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_setWithLength(StrArray *self, size_t pos, const char *val, size_t len)
{
    char *buf = (char *) malloc(len + 1);
    if (NULL == buf) {
        return -1;
    }   // end if
    strncpy(buf, val, len);
    buf[len] = '\0';
    int ret = PtrArray_set(self, pos, buf);
    if (0 > ret) {
        free(buf);
    }   // end if
    return ret;
}   // end function : StrArray_setWithLength

/**
 * StrArray オブジェクトの末尾に文字列を格納する
 * @param self StrArray オブジェクト
 * @param val 格納する文字列
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_append(StrArray *self, const char *val)
{
    return StrArray_set(self, StrArray_getCount(self), val);
}   // end function : StrArray_append


/**
 * StrArray オブジェクトの末尾に文字列を格納する
 * @param self StrArray オブジェクト
 * @param val 格納する文字列
 * @param len 格納する文字列のサイズ
 * @return 成功した場合は格納した要素の番号, 失敗した場合は -1
 */
int
StrArray_appendWithLength(StrArray *self, const char *val, size_t len)
{
    return StrArray_setWithLength(self, StrArray_getCount(self), val, len);
}   // end function : StrArray_appendWithLength

static int
StrArray_compareElement(const void *p1, const void *p2)
{
    return strcmp(*((const char **) p1), *((const char **) p2));
}   // end function : StrArray_compareElement

static int
StrArray_compareElementIgnoreCase(const void *p1, const void *p2)
{
    return strcasecmp(*((const char **) p1), *((const char **) p2));
}   // end function : StrPairArray_compareElementIgnoreCase

static int
StrArray_compareKey(const void *keyObj, const void *arrayElement)
{
    return strcmp((const char *) keyObj, *((const char **) arrayElement));
}   // end function : StrArray_compareKey

static int
StrArray_compareKeyIgnoreCase(const void *keyObj, const void *arrayElement)
{
    return strcasecmp((const char *) keyObj, *((const char **) arrayElement));
}   // end function : StrArray_compareKeyIgnoreCase

void
StrArray_sort(StrArray *self)
{
    assert(NULL != self);
    PtrArray_sort(self, StrArray_compareElement);
}   // end function : StrArray_sort

void
StrArray_sortIgnoreCase(StrArray *self)
{
    assert(NULL != self);
    PtrArray_sort(self, StrArray_compareElementIgnoreCase);
}   // end function : StrArray_sortIgnoreCase

int
StrArray_binarySearch(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_binarySearch(self, (void *) key, StrArray_compareKey, StrArray_compareElement);
}   // end function : StrArray_binarySearch

int
StrArray_binarySearchIgnoreCase(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_binarySearch(self, (void *) key, StrArray_compareKeyIgnoreCase,
                                 StrArray_compareElementIgnoreCase);
}   // end function : StrArray_binarySearchIgnoreCase

int
StrArray_linearSearch(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_linearSearch(self, (void *) key, StrArray_compareKey);
}   // end function : StrArray_linearSearch

int
StrArray_linearSearchIgnoreCase(StrArray *self, const char *key)
{
    assert(NULL != self);
    return PtrArray_linearSearch(self, (void *) key, StrArray_compareKeyIgnoreCase);
}   // end function : StrArray_linearSearchIgnoreCase

/**
 * 文字列を sep 区切った内容を要素として保持する StrArray オブジェクトを構築する.
 * @param record 文字列
 * @param sep セパレーター
 * @return 構築した StrArray オブジェクト, エラーが発生した場合は NULL
 * @note セパレーターが連続している場合は空の要素を生成する
 */
StrArray *
StrArray_split(const char *record, char sep)
{
    StrArray *self = StrArray_new(0);
    if (NULL == self) {
        return NULL;
    }   // end if

    const char *p;
    for (p = record; '\0' != *p;) {
        const char *psep = strchr(p, sep);
        if (NULL == psep) {
            break;
        }   // end if
        if (0 > StrArray_appendWithLength(self, p, psep - p)) {
            goto cleanup;
        }   // end if
        p = psep + 1;
    }   // end for

    // セパレーターが見つからないので, 残り全部を1つの要素として追加する
    if (0 > StrArray_append(self, p)) {
        goto cleanup;
    }   // end if
    return self;

  cleanup:
    if (NULL != self) {
        StrArray_free(self);
    }   // end if
    return NULL;
}   // end function : StrArray_split
