/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: inetdomain.c 54 2008-06-17 06:35:13Z takahiko $
 */
/**
 * @file
 * @brief ドメイン名操作用関数群
 * @version $Id: inetdomain.c 54 2008-06-17 06:35:13Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: inetdomain.c 54 2008-06-17 06:35:13Z takahiko $");

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include "inetdomain.h"

/**
 * 上から指定した深さのドメインを切り出す
 * @param depth 切り出すドメインの深さ，1以上を指定すること
 * @return domain のうち, 指定した深さのドメインを示すような文字列へのポインタ,
 */
const char *
InetDomain_parent(const char *domain, size_t depth)
{
    assert(NULL != domain);
    assert(0 < depth);

    const char *p = domain + strlen(domain) - 1;    // p を domain の末尾に移動する
    if (p < domain) {   // 長さ 0 の文字列を排除
        return domain;
    }   // end if
    if (*p == '.') {    // 末尾の '.' は数に入れない
        --p;
    }   // end if

    for (; 0 < depth && domain <= p; --p) { // domain の先頭に達するか
        if (*p == '.' && --depth == 0) {    // '.' が depth 回出現したら終了
            break;
        }   // end if
    }   // end for

    return p + 1;
}   // end function : InetDomain_parent

/**
 * 直上のドメインを抽出する
 * @param domain 処理対象とするドメイン
 * @return domain のうち, 直上のドメインを示すような文字列へのポインタ,
 *         domain の上にドメインがない (domain が最上位ドメインの) 場合は NULL
 */
const char *
InetDomain_upward(const char *domain)
{
    assert(NULL != domain);
    const char *p = strchr(domain, '.');
    return (NULL != p && *(p + 1) != '\0') ? p + 1 : NULL;
}   // end function : InetDomain_upward

/*
 * parent が child の親ドメインかどうかを調べる
 * @return parent が child の親ドメインまたは同一ドメインなら true,
 *         そうでない場合は false
 */
bool
InetDomain_isParent(const char *parent, const char *child)
{
    size_t parentlen = strlen(parent);
    if (parent[parentlen - 1] == '.') {
        --parentlen;
    }   // end if

    size_t childlen = strlen(child);
    const char *childpart = child + childlen - parentlen;
    if (child[childlen - 1] == '.') {
        --childpart;
    }   // end if

    if (childpart < child) {
        return false;
    }   // end if

    if (0 != strncasecmp(childpart, parent, parentlen)) {
        return false;
    }   // end if

    if (child < childpart && *(childpart - 1) != '.') {
        return false;
    }   // end if

    return true;
}   // end function : InetDomain_isParent

/*
 * domain1 と domain2 が同一ドメインかどうかを調べる
 * @return domain1 と domain2 が同一ドメインなら true,
 *         そうでない場合は false.
 */
bool
InetDomain_isMatch(const char *domain1, const char *domain2)
{
    size_t domlen1 = strlen(domain1);
    if (domain1[domlen1 - 1] == '.') {
        --domlen1;
    }   // end if

    size_t domlen2 = strlen(domain2);
    if (domain2[domlen2 - 1] == '.') {
        --domlen2;
    }   // end if

    if (domlen1 != domlen2) {
        return false;
    }   // end if

    if (0 != strncasecmp(domain1, domain2, domlen1)) {
        return false;
    }   // end if

    return true;
}   // end function : InetDomain_isMatch
