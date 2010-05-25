/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dnsresolv.c 349 2008-08-13 15:56:16Z takahiko $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "rcsid.h"
RCSID("$Id: dnsresolv.c 349 2008-08-13 15:56:16Z takahiko $");

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <resolv.h>

#ifndef HAVE_STRLCPY
# include "strlcpy.h"
#endif

#include "dnsresolv.h"

void
DnsResolver_free(DnsResolver *self)
{
    assert(NULL != self);
    res_nclose(&self->resolver);
    /*
     * glibc-2.4.0 以降ならば
     * res_nclose(&self->resolver);
     * とすることで libresolv でも対応可能.
     * glibc-2.3.x にも res_nclose() は存在するが,
     * マルチスレッド環境下ではメモリリークを引き起こす.
     */
    free(self);
}   // end function : DnsResolver_free

DnsResolver *
DnsResolver_new(void)
{
    DnsResolver *self = (DnsResolver *) malloc(sizeof(DnsResolver));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DnsResolver));
    if (NETDB_SUCCESS != res_ninit(&self->resolver)) {
        goto cleanup;
    }   // end if
    self->resolv_errno = 0;
    self->resolv_h_errno = NETDB_SUCCESS;
    return self;

  cleanup:
    DnsResolver_free(self);
    return NULL;
}   // end function : DnsResolver_init

void
DnsAResponse_free(DnsAResponse *self)
{
    assert(NULL != self);
    free(self);
}   // end function : DnsAResponse_free

void
DnsAaaaResponse_free(DnsAaaaResponse *self)
{
    assert(NULL != self);
    free(self);
}   // end function : DnsAaaaResponse_free

void
DnsMxResponse_free(DnsMxResponse *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->num; ++n) {
        free(self->exchange[n]);
    }   // end for
    free(self);
}   // end function : DnsMxResponse_free

void
DnsTxtResponse_free(DnsTxtResponse *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->num; ++n) {
        free(self->data[n]);
    }   // end for
    free(self);
}   // end function : DnsTxtResponse_free

void
DnsSpfResponse_free(DnsSpfResponse *self)
{
    DnsTxtResponse_free(self);
}   // end function : DnsSpfResponse_free

void
DnsPtrResponse_free(DnsPtrResponse *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->num; ++n) {
        free(self->domain[n]);
    }   // end for
    free(self);
}   // end function : DnsPtrResponse_free

static int
DnsResolver_rcode2statcode(int rcode)
{
    switch (rcode) {
    case ns_r_noerror:
        return NETDB_SUCCESS;
    case ns_r_nxdomain:
        return HOST_NOT_FOUND;
    case ns_r_servfail:
        return TRY_AGAIN;
    case ns_r_formerr:
    case ns_r_notimpl:
    case ns_r_refused:
    default:
        return NO_RECOVERY;
    }   // end switch
}   // end function : DnsResolver_rcode2statcode

static int
DnsResolver_setError(DnsResolver *self, int res_h_errno)
{
    self->resolv_h_errno = res_h_errno;
    self->resolv_errno = errno;
    return res_h_errno; // 呼び出し側の便宜のため
}   // end function : DnsResolver_setError

const char *
DnsResolver_getErrorString(DnsResolver *self)
{
    return (NETDB_INTERNAL == self->resolv_h_errno)
        ? strerror(self->resolv_errno) : hstrerror(self->resolv_h_errno);
}   // end function : DnsResolver_getErrorString

/*
 * クエリを投げる.
 * @return
 */
static int
DnsResolver_query(DnsResolver *self, const char *domain, int rrtype)
{
    self->resolver.res_h_errno = 0;
    self->resolv_errno = 0;
    self->resolv_h_errno = NETDB_SUCCESS;
    self->msglen = res_nquery(&self->resolver, domain, ns_c_in, rrtype, self->msgbuf, NS_MAXMSG);
    if (0 > self->msglen) {
        goto queryfail;
    }   // end if
    if (0 > ns_initparse(self->msgbuf, self->msglen, &self->msghanlde)) {
        self->resolver.res_h_errno = NO_RECOVERY;
        goto queryfail;
    }   // end if

    int rcode_flag = ns_msg_getflag(self->msghanlde, ns_f_rcode);
    if (rcode_flag != ns_r_noerror) {
        self->resolver.res_h_errno = DnsResolver_rcode2statcode(rcode_flag);
        goto queryfail;
    }   // end if

    return NETDB_SUCCESS;

  queryfail:
    return DnsResolver_setError(self, self->resolver.res_h_errno);
}   // end function : DnsResolver_query

int
DnsResolver_lookupA(DnsResolver *self, const char *domain, DnsAResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, ns_t_a);
    if (NETDB_SUCCESS != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsAResponse *respobj =
        (DnsAResponse *) malloc(sizeof(DnsAResponse) + msg_count * sizeof(struct in_addr));
    if (NULL == respobj) {
        return DnsResolver_setError(self, NETDB_INTERNAL);
    }   // end if
    memset(respobj, 0, sizeof(DnsAResponse) + msg_count * sizeof(struct in_addr));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_a != ns_rr_type(rr)) {
            continue;
        }   // end if
        if (NS_INADDRSZ != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        memcpy(&(respobj->addr[respobj->num]), ns_rr_rdata(rr), NS_INADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto formerr;
    }   // end if
    *resp = respobj;
    return NETDB_SUCCESS;

  formerr:
    DnsAResponse_free(respobj);
    return DnsResolver_setError(self, NO_RECOVERY);
}   // end function : DnsResolver_lookupA

int
DnsResolver_lookupAaaa(DnsResolver *self, const char *domain, DnsAaaaResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, ns_t_aaaa);
    if (NETDB_SUCCESS != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsAaaaResponse *respobj =
        (DnsAaaaResponse *) malloc(sizeof(DnsAaaaResponse) + msg_count * sizeof(struct in6_addr));
    if (NULL == respobj) {
        return DnsResolver_setError(self, NETDB_INTERNAL);
    }   // end if
    memset(respobj, 0, sizeof(DnsAaaaResponse) + msg_count * sizeof(struct in6_addr));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_aaaa != ns_rr_type(rr)) {
            continue;
        }   // end if
        if (NS_IN6ADDRSZ != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        memcpy(&(respobj->addr[respobj->num]), ns_rr_rdata(rr), NS_IN6ADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto formerr;
    }   // end if
    *resp = respobj;
    return NETDB_SUCCESS;

  formerr:
    DnsAaaaResponse_free(respobj);
    return DnsResolver_setError(self, NO_RECOVERY);
}   // end function : DnsResolver_lookupAaaa

int
DnsResolver_lookupMx(DnsResolver *self, const char *domain, DnsMxResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, ns_t_mx);
    if (NETDB_SUCCESS != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsMxResponse *respobj =
        (DnsMxResponse *) malloc(sizeof(DnsMxResponse) + msg_count * sizeof(struct mxentry *));
    if (NULL == respobj) {
        return DnsResolver_setError(self, NETDB_INTERNAL);
    }   // end if
    memset(respobj, 0, sizeof(DnsMxResponse) + msg_count * sizeof(struct mxentry *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_mx != ns_rr_type(rr)) {
            continue;
        }   // end if
        const unsigned char *rdata = ns_rr_rdata(rr);
        if (ns_rr_rdlen(rr) < NS_INT16SZ) {
            goto formerr;
        }   // end if

        int preference = ns_get16(rdata);
        rdata += NS_INT16SZ;

        // NOTE: NS_MAXDNAME で十分なのかイマイチ確証が持てないが, bind8 の dig コマンドの実装でもこの値を使っていたのでいいのではないか.
        char dnamebuf[NS_MAXDNAME];
        int dnamelen =
            ns_name_uncompress(self->msgbuf, self->msgbuf + self->msglen, rdata, dnamebuf,
                               sizeof(dnamebuf));
        if (NS_INT16SZ + dnamelen != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        // TODO: dnamebuf は NULL 終端が保証されているのか?
        size_t domainlen = strlen(dnamebuf);
        respobj->exchange[respobj->num] =
            (struct mxentry *) malloc(sizeof(struct mxentry) + sizeof(char[domainlen + 1]));
        if (NULL == respobj->exchange[respobj->num]) {
            goto noresource;
        }   // end if
        respobj->exchange[respobj->num]->preference = preference;
        if (domainlen + 1 <=
            strlcpy(respobj->exchange[respobj->num]->domain, dnamebuf, domainlen + 1)) {
            abort();
        }   // end if
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto formerr;
    }   // end if
    *resp = respobj;
    return NETDB_SUCCESS;

  formerr:
    DnsMxResponse_free(respobj);
    return DnsResolver_setError(self, NO_RECOVERY);

  noresource:
    DnsMxResponse_free(respobj);
    return DnsResolver_setError(self, NETDB_INTERNAL);
}   // end function : DnsResolver_lookupMx

/**
 * @return 成功した場合は NETDB_SUCCESS.
 */
static int
DnsResolver_lookupTxtData(DnsResolver *self, int rrtype, const char *domain, DnsTxtResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, rrtype);
    if (NETDB_SUCCESS != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsTxtResponse *respobj =
        (DnsTxtResponse *) malloc(sizeof(DnsTxtResponse) + msg_count * sizeof(char *));
    if (NULL == respobj) {
        return DnsResolver_setError(self, NETDB_INTERNAL);
    }   // end if
    memset(respobj, 0, sizeof(DnsTxtResponse) + msg_count * sizeof(char *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_txt != ns_rr_type(rr)) {
            continue;
        }   // end if
        respobj->data[respobj->num] = (char *) malloc(ns_rr_rdlen(rr)); // RDLEN を越えることはない.
        if (NULL == respobj->data[respobj->num]) {
            goto noresource;
        }   // end if
        const unsigned char *rdata = ns_rr_rdata(rr);
        const unsigned char *rdata_tail = ns_rr_rdata(rr) + ns_rr_rdlen(rr);
        char *bufp = respobj->data[respobj->num];
        while (rdata < rdata_tail) {
            // 長さフィールドが RDLEN の中に収まっているか確認する
            if (rdata_tail < rdata + (*rdata) + 1) {
                free(respobj->data[respobj->num]);
                goto formerr;
            }   // end if
            memcpy(bufp, rdata + 1, *rdata);
            bufp += (size_t) *rdata;
            rdata += (size_t) *rdata + 1;
        }   // end while
        *bufp = '\0';   // 扱いやすいように NULL 終端させる
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto formerr;
    }   // end if
    *resp = respobj;
    return NETDB_SUCCESS;

  formerr:
    DnsTxtResponse_free(respobj);
    return DnsResolver_setError(self, NO_RECOVERY);

  noresource:
    DnsTxtResponse_free(respobj);
    return DnsResolver_setError(self, NETDB_INTERNAL);
}   // end function : DnsResolver_lookupTxtData

int
DnsResolver_lookupTxt(DnsResolver *self, const char *domain, DnsTxtResponse **resp)
{
    return DnsResolver_lookupTxtData(self, ns_t_txt, domain, resp);
}   // end function : DnsResolver_lookupTxt

int
DnsResolver_lookupSpf(DnsResolver *self, const char *domain, DnsSpfResponse **resp)
{
    return DnsResolver_lookupTxtData(self, 99 /* as ns_t_spf */ , domain, resp);
}   // end function : DnsResolver_lookupSpf

/*
 * buflen のサイズは DNS_IP4_REVENT_MAXLEN 以上である必要がある.
 */
static bool
DnsResolver_expandReverseEntry4(const struct in_addr *addr4, char *buf, size_t buflen)
{
    const unsigned char *rawaddr = (const unsigned char *) addr4;
    int ret =
        snprintf(buf, buflen, "%hhu.%hhu.%hhu.%hhu." DNS_IP4_REVENT_SUFFIX, rawaddr[3], rawaddr[2],
                 rawaddr[1], rawaddr[0]);
    return (ret < (int) buflen) ? true : false;
}   // end function : DnsResolver_expandReverseEntry4

/*
 * 0 以上 15 以下の整数に対応する16進数の文字を返す.
 * p が [0,15] の範囲にあることが前提. それ以外の場合の動作は未定義.
 */
static char
xtoa(unsigned char p)
{
    return p < 0xa ? p + '0' : p + 'a' - 0xa;
}   // end function : xtoa

/*
 * buflen のサイズは DNS_IP6_REVENT_MAXLEN 以上である必要がある.
 */
static bool
DnsResolver_expandReverseEntry6(const struct in6_addr *addr6, char *buf, size_t buflen)
{
    if (buflen < DNS_IP6_REVENT_MAXLEN) {
        return false;
    }   // end if
    const unsigned char *rawaddr = (const unsigned char *) addr6;
    const unsigned char *rawaddr_tail = rawaddr + NS_IN6ADDRSZ;
    char *bufp = buf;
    for (; rawaddr < rawaddr_tail; ++rawaddr) {
        *(bufp++) = xtoa((*(rawaddr++) & 0xf0) >> 4);
        *(bufp++) = '.';
        *(bufp++) = xtoa(*(rawaddr++) & 0x0f);
        *(bufp++) = '.';
    }   // end for
    memcpy(bufp, DNS_IP6_REVENT_SUFFIX, sizeof(DNS_IP6_REVENT_SUFFIX)); // 終端のNULL文字もコピーする
    return true;
}   // end function : DnsResolver_expandReverseEntry6

int
DnsResolver_lookupPtr(DnsResolver *self, int af, const void *addr, DnsPtrResponse **resp)
{
    // IPv6 の逆引きエントリ名生成に十分な長さのバッファを確保する.
    char domain[DNS_IP6_REVENT_MAXLEN];
    switch (af) {
    case AF_INET:
        if (!DnsResolver_expandReverseEntry4(addr, domain, sizeof(domain))) {
            abort();
        }   // end if
        break;
    case AF_INET6:
        if (!DnsResolver_expandReverseEntry6(addr, domain, sizeof(domain))) {
            abort();
        }   // end if
        break;
    default:
        errno = EAFNOSUPPORT;
        return NETDB_INTERNAL;
    }   // end if

    int query_stat = DnsResolver_query(self, domain, ns_t_ptr);
    if (NETDB_SUCCESS != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsPtrResponse *respobj =
        (DnsPtrResponse *) malloc(sizeof(DnsPtrResponse) + msg_count * sizeof(char *));
    if (NULL == respobj) {
        return DnsResolver_setError(self, NETDB_INTERNAL);
    }   // end if
    memset(respobj, 0, sizeof(DnsPtrResponse) + msg_count * sizeof(char *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_ptr != ns_rr_type(rr)) {
            continue;
        }   // end if
        // NOTE: NS_MAXDNAME で十分なのかイマイチ確証が持てないが, bind8 の dig コマンドの実装でもこの値を使っていたのでいいのではないか.
        char dnamebuf[NS_MAXDNAME];
        int dnamelen =
            ns_name_uncompress(self->msgbuf, self->msgbuf + self->msglen, ns_rr_rdata(rr), dnamebuf,
                               sizeof(dnamebuf));
        if (dnamelen != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        respobj->domain[respobj->num] = strdup(dnamebuf);
        if (NULL == respobj->domain[respobj->num]) {
            goto noresource;
        }   // end if
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto formerr;
    }   // end if
    *resp = respobj;
    return NETDB_SUCCESS;

  formerr:
    DnsPtrResponse_free(respobj);
    return DnsResolver_setError(self, NO_RECOVERY);

  noresource:
    DnsPtrResponse_free(respobj);
    return DnsResolver_setError(self, NETDB_INTERNAL);
}   // end function : DnsResolver_lookupPtr
