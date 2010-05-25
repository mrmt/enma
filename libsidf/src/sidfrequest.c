/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfrequest.c 348 2008-08-13 15:44:32Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfrequest.c 348 2008-08-13 15:44:32Z takahiko $");

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
// #include <isc/misc.h>

#include "ptrop.h"
#include "loghandler.h"
#include "eventlogger.h"
#include "strarray.h"
#include "xskip.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "bitmemcmp.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "sidfenum.h"
#include "sidfrecord.h"
#include "sidfrequest.h"
#include "sidfmacro.h"

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#define SIDF_REQUEST_DEFAULT_LOCALPART "postmaster"

typedef struct SidfRawRecord {
    const char *record_head;
    const char *record_tail;
    const char *scope_tail;
    SidfRecordScope scope;
} SidfRawRecord;

static SidfScore SidfRequest_checkHost(SidfRequest *self, const char *domain);

static unsigned int
SidfRequest_getDepth(const SidfRequest *self)
{
    return self->redirect_depth + self->include_depth;
}   // end function : SidfRequest_getDepth

static SidfStat
SidfRequest_pushDomain(SidfRequest *self, const char *domain)
{
    if (0 <= StrArray_append(self->domain, domain)) {
        return SIDF_STAT_OK;
    } else {
        LogNoResource();
        return SIDF_STAT_NO_RESOURCE;
    }   // end if
}   // end function : SidfRequest_pushDomain

static void
SidfRequest_popDomain(SidfRequest *self)
{
    StrArray_unappend(self->domain);
}   // end function : SidfRequest_popDomain

const char *
SidfRequest_getDomain(const SidfRequest *self)
{
    size_t n = StrArray_getCount(self->domain);
    return 0 < n ? StrArray_get(self->domain, n - 1) : NULL;
}   // end function : SidfRequest_getDomain

static SidfScore
SidfRequest_getScoreByQualifier(SidfQualifier qualifier)
{
    // SidfQualifier は各スコアに対応する値を持たせているのでキャストするだけでよい
    return (SidfScore) qualifier;
}   // end function : SidfRequest_getScoreByQualifier

static SidfStat
SidfRequest_setExplanation(SidfRequest *self, const char *domain, const char *exp_macro)
{
    const char *nextp;
    XBuffer_reset(self->xbuf);
    SidfStat parse_stat =
        SidfMacro_parseExplainString(self, exp_macro, STRTAIL(exp_macro), &nextp, self->xbuf);
    if (SIDF_STAT_OK == parse_stat && STRTAIL(exp_macro) == nextp) {
        LogSidfDebug("explanation record: domain=%s, exp=%s", domain,
                     XBuffer_getString(self->xbuf));
        if (NULL != self->explanation) {
            // "exp=" の評価条件が重複している証拠なのでバグ
            LogImplError("clean up existing explanation: exp=%s", self->explanation);
            free(self->explanation);
            self->explanation = NULL;
        }   // end if
        // ignoring memory allocation error
        self->explanation = XBuffer_dupString(self->xbuf);
    } else {
        LogSidfNotice("explanation expansion failed: domain=%s, exp=%s", domain, exp_macro);
    }   // end if
    return parse_stat;
}   // end function : SidfRequest_setExplanation

/**
 * スコープに一致する唯一つのレコードを選択する.
 * @return スコープに一致するレコードが唯一つ見つかった場合, または見つからなかった場合は SIDF_SCORE_NULL,
 *         スコープに一致するレコードが複数見つかった場合は SIDF_SCORE_PERMERROR.
 */
static SidfScore
SidfRequest_uniqueByScope(const SidfRawRecord *rawrecords, unsigned int recordnum,
                          SidfRecordScope scope, const SidfRawRecord **selected)
{
    assert(NULL == *selected);

    for (size_t n = 0; n < recordnum; ++n) {
        if (scope & rawrecords[n].scope) {
            if (NULL == *selected) {
                *selected = &(rawrecords[n]);
            } else {
                // スコープに一致する SIDF レコードが複数存在した
                return SIDF_SCORE_PERMERROR;
            }   // end if
        }   // end if
    }   // end for

    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_uniqueByScope

/**
 * @return 成功した場合は SIDF_SCORE_NULL, SPFレコード取得の際にエラーが発生した場合は SIDF_SCORE_NULL 以外.
 */
static SidfScore
SidfRequest_fetch(const SidfRequest *self, const char *domain, DnsTxtResponse **txtresp)
{
    if (self->policy->lookup_spf_rr) {
        int spfquery_stat = DnsResolver_lookupSpf(self->resolver, domain, txtresp);
        switch (spfquery_stat) {
        case NETDB_SUCCESS:
            /*
             * RFC4406, 4408 とも SPF RR が存在した場合は全ての TXT RR を破棄するので,
             * SPF RR が見つかった場合は TXT RR をルックアップせずにこのまま戻せばよい.
             * [RFC4406] 4.4.
             * 1. If any records of type SPF are in the set, then all records of
             *    type TXT are discarded.
             * [RFC4408] 4.5.
             * 2. If any records of type SPF are in the set, then all records of
             *    type TXT are discarded.
             */
            return SIDF_SCORE_NULL;
        case NO_DATA:  // NOERROR
            // SPF RR がないので TXT RR にフォールバック
            break;
        case HOST_NOT_FOUND:   // NXDOMAIN
            /*
             * [RFC4406] 4.3.
             * When performing the PRA version of the test, if the DNS query returns
             * "non-existent domain" (RCODE 3), then check_host() exits immediately
             * with the result "Fail".
             * [RFC4408] 4.3.
             * If the <domain> is malformed (label longer than 63 characters, zero-
             * length label not at the end, etc.) or is not a fully qualified domain
             * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
             * check_host() immediately returns the result "None".
             */
            return (self->scope & SIDF_RECORD_SCOPE_SPF2_PRA)
                ? SIDF_SCORE_HARDFAIL : SIDF_SCORE_NONE;
        case NETDB_INTERNAL:
            return SIDF_SCORE_SYSERROR;
        case NO_RECOVERY:  // FORMERR, NOTIMP, REFUSED
        case TRY_AGAIN:    // SERVFAIL
        default:
            /*
             * [RFC4408] 4.4.
             * If all DNS lookups that are made return a server failure (RCODE 2),
             * or other error (RCODE other than 0 or 3), or time out, then
             * check_host() exits immediately with the result "TempError".
             */
            return SIDF_SCORE_TEMPERROR;
        }   // end switch
    }   // end if

    // TXT RR を引く
    int txtquery_stat = DnsResolver_lookupTxt(self->resolver, domain, txtresp);
    switch (txtquery_stat) {
    case NETDB_SUCCESS:
        return SIDF_SCORE_NULL;
    case NO_DATA:  // NOERROR
        /*
         * [RFC4406] 4.4.
         * If there are no matching records remaining after the initial DNS
         * query or any subsequent optional DNS queries, then check_host() exits
         * immediately with the result "None".
         * [RFC4408] 4.5.
         * If no matching records are returned, an SPF client MUST assume that
         * the domain makes no SPF declarations.  SPF processing MUST stop and
         * return "None".
         */
        return SIDF_SCORE_NONE;
    case HOST_NOT_FOUND:   // NXDOMAIN
        /*
         * [RFC4406] 4.3.
         * When performing the PRA version of the test, if the DNS query returns
         * "non-existent domain" (RCODE 3), then check_host() exits immediately
         * with the result "Fail".
         * [RFC4408] 4.3.
         * If the <domain> is malformed (label longer than 63 characters, zero-
         * length label not at the end, etc.) or is not a fully qualified domain
         * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
         * check_host() immediately returns the result "None".
         */
        return (self->scope & SIDF_RECORD_SCOPE_SPF2_PRA) ? SIDF_SCORE_HARDFAIL : SIDF_SCORE_NONE;
    case NETDB_INTERNAL:
        return SIDF_SCORE_SYSERROR;
    case NO_RECOVERY:  // FORMERR, NOTIMP, REFUSED
    case TRY_AGAIN:    // SERVFAIL
    default:
        /*
         * [RFC4408] 4.4.
         * If all DNS lookups that are made return a server failure (RCODE 2),
         * or other error (RCODE other than 0 or 3), or time out, then
         * check_host() exits immediately with the result "TempError".
         */
        return SIDF_SCORE_TEMPERROR;
    }   // end switch
}   // end function : SidfRequest_fetch

static SidfScore
SidfRequest_lookupRecord(const SidfRequest *self, const char *domain, SidfRecord **record)
{
    DnsTxtResponse *txtresp = NULL;
    SidfScore fetch_score = SidfRequest_fetch(self, domain, &txtresp);
    if (SIDF_SCORE_NULL != fetch_score) {
        return fetch_score;
    }   // end if
    assert(NULL != txtresp);

    // 各レコードのスコープを調べる
    SidfRawRecord rawrecords[txtresp->num];
    for (size_t n = 0; n < txtresp->num; ++n) {
        rawrecords[n].record_head = txtresp->data[n];
        rawrecords[n].record_tail = STRTAIL(txtresp->data[n]);
        (void) SidfRecord_getSidfScope(rawrecords[n].record_head, rawrecords[n].record_tail,
                                       &(rawrecords[n].scope), &(rawrecords[n].scope_tail));
    }   // end for

    // SIDF なスコープを持つ場合は SIDF レコードを探す
    const SidfRawRecord *selected = NULL;
    if (self->scope & (SIDF_RECORD_SCOPE_SPF2_MFROM | SIDF_RECORD_SCOPE_SPF2_PRA)) {
        SidfScore select_score =
            SidfRequest_uniqueByScope(rawrecords, txtresp->num, self->scope, &selected);
        if (SIDF_SCORE_NULL != select_score) {
            LogPermFail
                ("multiple spf2 record found: domain=%s, spf2-mfrom=%s, spf2-pra=%s",
                 domain, self->scope & SIDF_RECORD_SCOPE_SPF2_MFROM ? "true" : "false",
                 self->scope & SIDF_RECORD_SCOPE_SPF2_PRA ? "true" : "false");
            DnsTxtResponse_free(txtresp);
            return select_score;
        }   // end if
    }   // end if

    // SPFv1 なスコープを持つ場合, SIDF なスコープを持つが SIDF レコードが見つからなかった場合は SPF レコードを探す
    if (NULL == selected) {
        SidfScore select_score =
            SidfRequest_uniqueByScope(rawrecords, txtresp->num, SIDF_RECORD_SCOPE_SPF1,
                                      &selected);
        if (SIDF_SCORE_NULL != select_score) {
            LogPermFail("multiple spf1 record found: domain=%s, spf1=%s", domain,
                        self->scope & SIDF_RECORD_SCOPE_SPF1 ? "true" : "false");
            DnsTxtResponse_free(txtresp);
            return select_score;
        }   // end if
    }   // end if

    if (NULL == selected) {
        // スコープに一致する SPF/SIDF レコードが存在しなかった
        LogDebug("no spf record found: domain=%s, spf1=%s, spf2-mfrom=%s, spf2-pra=%s",
                 domain, self->scope & SIDF_RECORD_SCOPE_SPF1 ? "true" : "false",
                 self->scope & SIDF_RECORD_SCOPE_SPF2_MFROM ? "true" : "false",
                 self->scope & SIDF_RECORD_SCOPE_SPF2_PRA ? "true" : "false");
        DnsTxtResponse_free(txtresp);
        return SIDF_SCORE_NONE;
    }   // end if

    // スコープに一致する SPF/SIDF レコードが唯一つ存在した
    // レコードのパース
    SidfStat build_stat =
        SidfRecord_build(self, selected->scope, selected->scope_tail, selected->record_tail,
                         record);
    DnsTxtResponse_free(txtresp);
    switch (build_stat) {
    case SIDF_STAT_OK:
        return SIDF_SCORE_NULL;
    case SIDF_STAT_NO_RESOURCE:
        return SIDF_SCORE_SYSERROR;
    default:
        return SIDF_SCORE_PERMERROR;
    }   // end switch
}   // end function : SidfRequest_lookupRecord

static const char *
SidfRequest_getTargetName(const SidfRequest *self, const SidfTerm *term)
{
    return term->querydomain ? term->querydomain : SidfRequest_getDomain(self);
}   // end function : SidfRequest_getTargetName

/*
 * メカニズム評価中の DNS レスポンスエラーコードを SIDF のスコアにマップする.
 */
static SidfScore
SidfRequest_mapMechDnsResponseToSidfScore(int resolv_stat)
{
    /*
     * [RFC4408 5.]
     * Several mechanisms rely on information fetched from DNS.  For these
     * DNS queries, except where noted, if the DNS server returns an error
     * (RCODE other than 0 or 3) or the query times out, the mechanism
     * throws the exception "TempError".  If the server returns "domain does
     * not exist" (RCODE 3), then evaluation of the mechanism continues as
     * if the server returned no error (RCODE 0) and zero answer records.
     */
    switch (resolv_stat) {
    case NETDB_SUCCESS:
    case HOST_NOT_FOUND:
    case NO_DATA:
        return SIDF_SCORE_NULL;
    case NETDB_INTERNAL:
        return SIDF_SCORE_SYSERROR;
    case NO_RECOVERY:
    case TRY_AGAIN:
    default:
        return SIDF_SCORE_TEMPERROR;
    }   // end switch
}   // end function : SidfRequest_mapMechDnsResponseToSidfScore

static SidfScore
SidfRequest_incrementDnsMechCounter(SidfRequest *self)
{
    if (++(self->dns_mech_count) <= self->policy->max_dns_mech) {
        return SIDF_SCORE_NULL;
    } else {
        LogPermFail("over %d mechanisms with dns look up evaluated: sender=%s, domain=%s",
                    self->policy->max_dns_mech, InetMailbox_getDomain(self->sender),
                    SidfRequest_getDomain(self));
        return SIDF_SCORE_PERMERROR;
    }   // end if
}   // end function : SidfRequest_incrementDnsMechCounter

static SidfScore
SidfRequest_evalMechAll(SidfRequest *self, const SidfTerm *term)
{
    // "+all" に遭遇した場合, logging_pass_all_directive が有効ならログに出力する
    if (self->policy->logging_plus_all_directive && SIDF_QUALIFIER_PLUS == term->qualifier) {
        LogSidfNotice("Found +all directive in SPF record: domain=%s", SidfRequest_getDomain(self));
    }   // end if
    return SIDF_SCORE_NULL == self->policy->overwrite_all_directive_score
        ? SidfRequest_getScoreByQualifier(term->qualifier)
        : self->policy->overwrite_all_directive_score;
}   // end function : SidfRequest_evalMechAll

static SidfScore
SidfRequest_evalMechInclude(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    ++(self->include_depth);
    SidfScore eval_score = SidfRequest_checkHost(self, term->querydomain);
    --(self->include_depth);
    switch (eval_score) {
    case SIDF_SCORE_PASS:
        return SidfRequest_getScoreByQualifier(term->qualifier);
    case SIDF_SCORE_HARDFAIL:
    case SIDF_SCORE_SOFTFAIL:
    case SIDF_SCORE_NEUTRAL:
        return SIDF_SCORE_NULL;
    case SIDF_SCORE_TEMPERROR:
        return SIDF_SCORE_TEMPERROR;
    case SIDF_SCORE_PERMERROR:
    case SIDF_SCORE_NONE:
        return SIDF_SCORE_PERMERROR;
    case SIDF_SCORE_SYSERROR:
        return SIDF_SCORE_SYSERROR;
    case SIDF_SCORE_NULL:
    default:
        abort();
    }   // end switch
}   // end function : SidfRequest_evalMechInclude

/*
 * "a" メカニズムと "mx" メカニズムの共通部分を実装する関数
 */
static SidfScore
SidfRequest_evalByALookup(SidfRequest *self, const char *domain, const SidfTerm *term)
{
    size_t n;
    switch (self->sin_family) {
    case AF_INET:;
        DnsAResponse *resp4;
        int query4_stat = DnsResolver_lookupA(self->resolver, domain, &resp4);
        if (NETDB_SUCCESS != query4_stat) {
            LogDnsError("DNS lookup failure: rrtype=a, domain=%s, err=%s", domain,
                        DnsResolver_getErrorString(self->resolver));
            return SidfRequest_mapMechDnsResponseToSidfScore(query4_stat);
        }   // end if

        for (n = 0; n < resp4->num; ++n) {
            if (0 == bitmemcmp(&(self->ipaddr.addr4), &(resp4->addr[n]), term->ip4cidr)) {
                DnsAResponse_free(resp4);
                return SidfRequest_getScoreByQualifier(term->qualifier);
            }   // end if
        }   // end for
        DnsAResponse_free(resp4);
        break;

    case AF_INET6:;
        DnsAaaaResponse *resp6;
        int query6_stat = DnsResolver_lookupAaaa(self->resolver, domain, &resp6);
        if (NETDB_SUCCESS != query6_stat) {
            LogDnsError("DNS lookup failure: rrtype=aaaa, domain=%s, err=%s", domain,
                        DnsResolver_getErrorString(self->resolver));
            return SidfRequest_mapMechDnsResponseToSidfScore(query6_stat);
        }   // end if

        for (n = 0; n < resp6->num; ++n) {
            if (0 == bitmemcmp(&(self->ipaddr.addr6), &(resp6->addr[n]), term->ip6cidr)) {
                DnsAaaaResponse_free(resp6);
                return SidfRequest_getScoreByQualifier(term->qualifier);
            }   // end if
        }   // end for
        DnsAaaaResponse_free(resp6);
        break;

    default:
        abort();
    }   // end if

    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalByALookup

static SidfScore
SidfRequest_evalMechA(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    const char *domain = SidfRequest_getTargetName(self, term);
    return SidfRequest_evalByALookup(self, domain, term);
}   // end function : SidfRequest_evalMechA

static SidfScore
SidfRequest_evalMechMx(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    const char *domain = SidfRequest_getTargetName(self, term);
    DnsMxResponse *respmx;
    int mxquery_stat = DnsResolver_lookupMx(self->resolver, domain, &respmx);
    if (NETDB_SUCCESS != mxquery_stat) {
        LogDnsError("DNS lookup failure: rrtype=mx, domain=%s, err=%s", domain,
                    DnsResolver_getErrorString(self->resolver));
        return SidfRequest_mapMechDnsResponseToSidfScore(mxquery_stat);
    }   // end if

    /*
     * [RFC4408] 5.4.
     * check_host() first performs an MX lookup on the <target-name>.  Then
     * it performs an address lookup on each MX name returned.  The <ip> is
     * compared to each returned IP address.  To prevent Denial of Service
     * (DoS) attacks, more than 10 MX names MUST NOT be looked up during the
     * evaluation of an "mx" mechanism (see Section 10).  If any address
     * matches, the mechanism matches.
     */
    for (size_t n = 0; n < MIN(respmx->num, self->policy->max_mxrr_per_mxmech); ++n) {
        SidfScore score = SidfRequest_evalByALookup(self, respmx->exchange[n]->domain, term);
        if (SIDF_SCORE_NULL != score) {
            DnsMxResponse_free(respmx);
            return score;
        }   // end if
    }   // end for
    DnsMxResponse_free(respmx);
    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechMx

static SidfScore
SidfRequest_evalMechPtrValidate4(SidfRequest *self, const SidfTerm *term, const char *revdomain)
{
    DnsAResponse *resp;
    int query_stat = DnsResolver_lookupA(self->resolver, revdomain, &resp);
    if (NETDB_SUCCESS != query_stat) {
        /*
         * "ptr" メカニズムの評価中に A レコードのルックアップでエラーが発生した場合,
         * そのドメイン名をスキップして評価を続行する.
         * [RFC4408] 5.5.
         * If a DNS error occurs while doing the PTR RR lookup, then this
         * mechanism fails to match.  If a DNS error occurs while doing an A RR
         * lookup, then that domain name is skipped and the search continues.
         */
        LogDnsError("DNS lookup failure (ignored): rrtype=a, domain=%s, err=%s", revdomain,
                    DnsResolver_getErrorString(self->resolver));
        return SIDF_SCORE_NULL;
    }   // end if
    for (size_t m = 0; m < resp->num; ++m) {
        /*
         * revdomain が domain で終わっていれば match
         * [RFC4408] 5.5.
         * Check all validated domain names to see if they end in the
         * <target-name> domain.  If any do, this mechanism matches.  If no
         * validated domain name can be found, or if none of the validated
         * domain names end in the <target-name>, this mechanism fails to match.
         * (snip)
         * This mechanism matches if the <target-name> is either an ancestor of
         * a validated domain name or if the <target-name> and a validated
         * domain name are the same.  For example: "mail.example.com" is within
         * the domain "example.com", but "mail.bad-example.com" is not.
         */
        if (0 == memcmp(&(resp->addr[m]), &(self->ipaddr.addr4), NS_INADDRSZ)) {
            DnsAResponse_free(resp);
            return SidfRequest_getScoreByQualifier(term->qualifier);
        }   // end if
    }   // end for
    DnsAResponse_free(resp);
    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechPtrValidate4

static SidfScore
SidfRequest_evalMechPtrValidate6(SidfRequest *self, const SidfTerm *term, const char *revdomain)
{
    // ロジックに関する詳細は SidfRequest_evalMechPtrValidate4() のコメントと重複するので省略
    DnsAaaaResponse *resp;
    int query_stat = DnsResolver_lookupAaaa(self->resolver, revdomain, &resp);
    if (NETDB_SUCCESS != query_stat) {
        LogDnsError("DNS lookup failure (ignored): rrtype=aaaa, domain=%s, err=%s", revdomain,
                    DnsResolver_getErrorString(self->resolver));
        return SIDF_SCORE_NULL;
    }   // end if
    for (size_t m = 0; m < resp->num; ++m) {
        if (0 == memcmp(&(resp->addr[m]), &(self->ipaddr.addr6), NS_IN6ADDRSZ)) {
            DnsAaaaResponse_free(resp);
            return SidfRequest_getScoreByQualifier(term->qualifier);
        }   // end if
    }   // end for
    DnsAaaaResponse_free(resp);
    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechPtrValidate6

static SidfScore
SidfRequest_evalMechPtr(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    const char *domain = SidfRequest_getTargetName(self, term);
    DnsPtrResponse *respptr;
    int ptrquery_stat =
        DnsResolver_lookupPtr(self->resolver, self->sin_family, &(self->ipaddr), &respptr);
    if (NETDB_SUCCESS != ptrquery_stat) {
        /*
         * "ptr" メカニズムの評価中に PTR レコードのルックアップでエラーが発生した場合,
         * このメカニズムにマッチしなかったという扱いになる.
         * [RFC4408] 5.5.
         * If a DNS error occurs while doing the PTR RR lookup, then this
         * mechanism fails to match.  If a DNS error occurs while doing an A RR
         * lookup, then that domain name is skipped and the search continues.
         */
        char addrbuf[INET6_ADDRSTRLEN];
        (void) inet_ntop(self->sin_family, &(self->ipaddr), addrbuf, sizeof(addrbuf));
        LogDnsError("DNS lookup failure (ignored): rrtype=ptr, ipaddr=%s, err=%s", addrbuf,
                    DnsResolver_getErrorString(self->resolver));
        return SIDF_SCORE_NULL;
    }   // end if

    /*
     * [RFC4408] 5.5.
     * First, the <ip>'s name is looked up using this procedure: perform a
     * DNS reverse-mapping for <ip>, looking up the corresponding PTR record
     * in "in-addr.arpa." if the address is an IPv4 one and in "ip6.arpa."
     * if it is an IPv6 address.  For each record returned, validate the
     * domain name by looking up its IP address.  To prevent DoS attacks,
     * more than 10 PTR names MUST NOT be looked up during the evaluation of
     * a "ptr" mechanism (see Section 10).  If <ip> is among the returned IP
     * addresses, then that domain name is validated.
     */
    for (size_t n = 0; n < MIN(respptr->num, self->policy->max_ptrrr_per_ptrmech); ++n) {
        // アルゴリズムをよく読むと validated domain が <target-name> で終わっているかどうかの判断を
        // 先におこなった方が DNS ルックアップの回数が少なくて済む場合があることがわかる.
        if (!InetDomain_isParent(domain, respptr->domain[n])) {
            continue;
        }   // end if

        SidfScore score;
        switch (self->sin_family) {
        case AF_INET:
            score = SidfRequest_evalMechPtrValidate4(self, term, respptr->domain[n]);
            break;
        case AF_INET6:
            score = SidfRequest_evalMechPtrValidate6(self, term, respptr->domain[n]);
            break;
        default:
            abort();
        }   // end switch
        if (SIDF_SCORE_NULL != score) {
            DnsPtrResponse_free(respptr);
            return score;
        }   // end if
    }   // end for
    DnsPtrResponse_free(respptr);
    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechPtr

static SidfScore
SidfRequest_evalMechIp4(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_IP4 == term->attr->param_type);
    return (AF_INET == self->sin_family
            && 0 == bitmemcmp(&(self->ipaddr.addr4), &(term->param.addr4), term->ip4cidr))
        ? SidfRequest_getScoreByQualifier(term->qualifier) : SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechIp4

static SidfScore
SidfRequest_evalMechIp6(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_IP6 == term->attr->param_type);
    return (AF_INET6 == self->sin_family
            && 0 == bitmemcmp(&(self->ipaddr.addr6), &(term->param.addr6), term->ip6cidr))
        ? SidfRequest_getScoreByQualifier(term->qualifier) : SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechIp6

static SidfScore
SidfRequest_evalMechExists(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    DnsAResponse *resp;
    int aquery_stat = DnsResolver_lookupA(self->resolver, term->querydomain, &resp);
    if (NETDB_SUCCESS != aquery_stat) {
        LogDnsError("DNS lookup failure: rrtype=a, domain=%s, err=%s", term->querydomain,
                    DnsResolver_getErrorString(self->resolver));
        return SidfRequest_mapMechDnsResponseToSidfScore(aquery_stat);
    }   // end if

    size_t num = resp->num;
    DnsAResponse_free(resp);
    return (0 < num) ? SidfRequest_getScoreByQualifier(term->qualifier) : SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalMechExists

static SidfScore
SidfRequest_evalModRedirect(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    SidfScore incr_stat = SidfRequest_incrementDnsMechCounter(self);
    if (SIDF_SCORE_NULL != incr_stat) {
        return incr_stat;
    }   // end if
    ++(self->redirect_depth);
    SidfScore eval_score = SidfRequest_checkHost(self, term->querydomain);
    --(self->redirect_depth);
    /*
     * [RFC4408] 6.1.
     * The result of this new evaluation of check_host() is then considered
     * the result of the current evaluation with the exception that if no
     * SPF record is found, or if the target-name is malformed, the result
     * is a "PermError" rather than "None".
     */
    return SIDF_SCORE_NONE == eval_score ? SIDF_SCORE_PERMERROR : eval_score;
}   // end function : SidfRequest_evalModRedirect

static SidfStat
SidfRequest_evalModExplanation(SidfRequest *self, const SidfTerm *term)
{
    /*
     * [RFC4408] 6.2.
     * If <domain-spec> is empty, or there are any DNS processing errors
     * (any RCODE other than 0), or if no records are returned, or if more
     * than one record is returned, or if there are syntax errors in the
     * explanation string, then proceed as if no exp modifier was given.
     */

    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

    DnsTxtResponse *resp;
    int txtquery_stat = DnsResolver_lookupTxt(self->resolver, term->querydomain, &resp);
    if (NETDB_SUCCESS != txtquery_stat) {
        LogDnsError("DNS lookup failure: rrtype=txt, domain=%s, err=%s", term->querydomain,
                    DnsResolver_getErrorString(self->resolver));
        return SIDF_STAT_OK;
    }   // end if

    if (1 != resp->num) {
        DnsTxtResponse_free(resp);
        return SIDF_STAT_OK;
    }   // end if

    SidfStat expand_stat = SidfRequest_setExplanation(self, term->querydomain, resp->data[0]);
    DnsTxtResponse_free(resp);
    return expand_stat;
}   // end function : SidfRequest_evalModExplanation

static SidfScore
SidfRequest_evalMechanism(SidfRequest *self, const SidfTerm *term)
{
    assert(NULL != term);
    assert(NULL != term->attr);

    if (term->attr->involve_dnslookup) {
        SidfScore incr_stat = SidfRequest_incrementDnsMechCounter(self);
        if (SIDF_SCORE_NULL != incr_stat) {
            return incr_stat;
        }   // end if
    }   // end if

    switch (term->attr->type) {
    case SIDF_TERM_MECH_ALL:
        return SidfRequest_evalMechAll(self, term);
    case SIDF_TERM_MECH_INCLUDE:
        return SidfRequest_evalMechInclude(self, term);
    case SIDF_TERM_MECH_A:
        return SidfRequest_evalMechA(self, term);
    case SIDF_TERM_MECH_MX:
        return SidfRequest_evalMechMx(self, term);
    case SIDF_TERM_MECH_PTR:
        return SidfRequest_evalMechPtr(self, term);
    case SIDF_TERM_MECH_IP4:
        return SidfRequest_evalMechIp4(self, term);
    case SIDF_TERM_MECH_IP6:
        return SidfRequest_evalMechIp6(self, term);
    case SIDF_TERM_MECH_EXISTS:
        return SidfRequest_evalMechExists(self, term);
    default:
        abort();
    }   // end switch
}   // end function : SidfRequest_evalMechanism

static SidfScore
SidfRequest_checkDomain(const SidfRequest *self, const char *domain)
{
    /*
     * 引数 <domain> の検証
     *
     * [RFC4408] 4.3.
     * If the <domain> is malformed (label longer than 63 characters, zero-
     * length label not at the end, etc.) or is not a fully qualified domain
     * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
     * check_host() immediately returns the result "None".
     */
    size_t domain_len = strlen(domain);
    if (self->policy->max_domain_len < domain_len) {
        LogPermFail("<domain> length for check_host too long: length=%u, domain(50)=%.50s",
                    (unsigned int) domain_len, domain);
        return SIDF_SCORE_NONE;
    }   // end if

    // 文字種のチェック. 2821-Domain だとキツいのでちょっと緩め.
    const char *p;
    const char *domain_tail = domain + domain_len;
    XSkip_dotAtomText(domain, domain_tail, &p);
    XSkip_char(p, domain_tail, '.', &p);
    if (domain_tail != p) {
        LogPermFail("<domain> for check_host doesn't match domain-name: domain=%s", domain);
        return SIDF_SCORE_NONE;
    }   // end if

    // "include" mechanism や "redirect=" modifier でループを形成していないかチェックする.
    if (0 <= StrArray_linearSearchIgnoreCase(self->domain, domain)) {
        LogPermFail("evaluation loop detected: domain=%s", domain);
        return SIDF_SCORE_PERMERROR;
    }   // end if

    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_checkDomain

static SidfScore
SidfRequest_evalDirectives(SidfRequest *self, const PtrArray *directives)
{
    const char *domain = SidfRequest_getDomain(self);
    unsigned int directive_num = PtrArray_getCount(directives);
    for (unsigned int i = 0; i < directive_num; ++i) {
        SidfTerm *term = PtrArray_get(directives, i);
        SidfScore eval_score = SidfRequest_evalMechanism(self, term);
        if (SIDF_SCORE_NULL != eval_score) {
            LogSidfDebug("mechanism match: domain=%s, mech%02u=%s, score=%s", domain, i,
                         term->attr->name, SidfEnum_lookupScoreByValue(eval_score));
            return eval_score;
        }   // end if
        LogSidfDebug("mechanism not match: domain=%s, mech_no=%u, mech=%s", domain, i,
                     term->attr->name);
    }   // end if
    return SIDF_SCORE_NULL;
}   // end function : SidfRequest_evalDirectives

static SidfScore
SidfRequest_evalLocalPolicy(SidfRequest *self)
{
    // 再帰評価 (include や redirect) の内側にいない場合のみ, ローカルポリシーの評価をおこなう
    if (0 < SidfRequest_getDepth(self) || NULL == self->policy->local_policy
        || self->local_policy_mode) {
        return SIDF_SCORE_NULL;
    }   // end if

    LogSidfDebug("evaluating local policy: policy=%s", self->policy->local_policy);
    // SPF/SIDF 評価過程で遭遇した DNS をひくメカニズムのカウンタをクリア
    SidfRecord *local_policy_record = NULL;
    SidfStat build_stat = SidfRecord_build(self, self->scope, self->policy->local_policy,
                                           STRTAIL(self->policy->local_policy),
                                           &local_policy_record);
    if (SIDF_STAT_OK != build_stat) {
        LogConfigError("failed to build local policy record: policy=%s",
                       self->policy->local_policy);
        return SIDF_SCORE_NULL;
    }   // end if
    self->dns_mech_count = 0;   // 本物のレコード評価中に遭遇した DNS ルックアップを伴うメカニズムの数は忘れる
    self->local_policy_mode = true; // ローカルポリシー評価中に, さらにローカルポリシーを適用して無限ループに入らないようにフラグを立てる.
    SidfScore local_policy_score =
        SidfRequest_evalDirectives(self, local_policy_record->directives);
    self->local_policy_mode = false;
    SidfRecord_free(local_policy_record);

    switch (local_policy_score) {
    case SIDF_SCORE_PERMERROR:
    case SIDF_SCORE_TEMPERROR:
        // ローカルポリシー評価中の temperror, permerror は無視する
        LogSidfDebug("ignoring local policy score: score=%s",
                     SidfEnum_lookupScoreByValue(local_policy_score));
        return SIDF_SCORE_NULL;
    default:
        LogSidfDebug("applying local policy score: score=%s",
                     SidfEnum_lookupScoreByValue(local_policy_score));
        return local_policy_score;
    }   // end switch
}   // end function : SidfRequest_evalLocalPolicy

static SidfScore
SidfRequest_checkHost(SidfRequest *self, const char *domain)
{
    // check <domain> parameter
    SidfScore precond_score = SidfRequest_checkDomain(self, domain);
    if (SIDF_SCORE_NULL != precond_score) {
        return precond_score;
    }   // end if

    // register <domain> parameter
    SidfStat push_stat = SidfRequest_pushDomain(self, domain);
    if (SIDF_STAT_OK != push_stat) {
        return SIDF_SCORE_SYSERROR;
    }   // end if

    SidfRecord *record = NULL;
    SidfScore lookup_score = SidfRequest_lookupRecord(self, SidfRequest_getDomain(self), &record);
    if (SIDF_SCORE_NULL != lookup_score) {
        SidfRequest_popDomain(self);
        return lookup_score;
    }   // end if

    // mechanism evaluation
    SidfScore eval_score = SidfRequest_evalDirectives(self, record->directives);
    if (SIDF_SCORE_NULL != eval_score) {
        /*
         * SidfPolicy で "exp=" を取得するようの指定されている場合に "exp=" を取得する.
         * ただし, 以下の点に注意する:
         * - include メカニズム中の exp= は評価しない.
         * - redirect 評価中に元のドメインの exp= は評価しない.
         * [RFC4408] 6.2.
         * Note: During recursion into an "include" mechanism, an exp= modifier
         * from the <target-name> MUST NOT be used.  In contrast, when executing
         * a "redirect" modifier, an exp= modifier from the original domain MUST
         * NOT be used.
         *
         * <target-name> は メカニズムの引数で指定されている <domain-spec>,
         * 指定されていない場合は check_host() 関数の <domain>.
         * [RFC4408] 4.8.
         * Several of these mechanisms and modifiers have a <domain-spec>
         * section.  The <domain-spec> string is macro expanded (see Section 8).
         * The resulting string is the common presentation form of a fully-
         * qualified DNS name: a series of labels separated by periods.  This
         * domain is called the <target-name> in the rest of this document.
         */
        if (self->policy->lookup_exp && SIDF_SCORE_HARDFAIL == eval_score
            && 0 == self->include_depth && NULL != record->modifiers.exp) {
            (void) SidfRequest_evalModExplanation(self, record->modifiers.exp);
        }   // end if
        goto finally;
    }   // end if

    /*
     * レコード中の全てのメカニズムにマッチしなかった場合
     * [RFC4408] 4.7.
     * If none of the mechanisms match and there is no "redirect" modifier,
     * then the check_host() returns a result of "Neutral", just as if
     * "?all" were specified as the last directive.  If there is a
     * "redirect" modifier, check_host() proceeds as defined in Section 6.1.
     */

    // "redirect=" modifier evaluation
    if (NULL != record->modifiers.rediect) {
        LogSidfDebug("redirect: from=%s, to=%s", domain, record->modifiers.rediect->param.domain);
        eval_score = SidfRequest_evalModRedirect(self, record->modifiers.rediect);
        goto finally;
    }   // end if

    eval_score = SidfRequest_evalLocalPolicy(self);
    if (SIDF_SCORE_NULL != eval_score) {
        // exp= を評価する条件は directive によってスコアが決定する場合とほぼ同じ.
        // 違いは local_policy_explanation を使用する点.
        if (self->policy->lookup_exp && SIDF_SCORE_HARDFAIL == eval_score
            && 0 == self->include_depth && NULL != self->policy->local_policy_explanation) {
            // local policy 専用の explanation をセットする.
            (void) SidfRequest_setExplanation(self, domain, self->policy->local_policy_explanation);
        }   // end if
        goto finally;
    }   // end if

    // returns "Neutral" as default socre
    eval_score = SIDF_SCORE_NEUTRAL;
    LogSidfDebug("default score applied: domain=%s", domain);

  finally:
    SidfRequest_popDomain(self);
    SidfRecord_free(record);
    return eval_score;
}   // end function : SidfRequest_checkHost

/**
 * HELO は指定必須. sender が指定されていない場合, postmaster@(HELOとして指定したドメイン) を sender として使用する.
 * @return SIDF_SCORE_NULL: 引数がセットされていない.
 *         SIDF_SCORE_SYSERROR: メモリの確保に失敗した.
 *         それ以外の場合は評価結果.
 */
SidfScore
SidfRequest_eval(SidfRequest *self, SidfRecordScope scope)
{
    assert(NULL != self);

    self->scope = scope;
    self->dns_mech_count = 0;
    if (0 == self->sin_family || NULL == self->helo_domain) {
        return SIDF_SCORE_NULL;
    }   // end if
    if (NULL == self->sender) {
        /*
         * [RFC4408] 4.3.
         * If the <sender> has no localpart, substitute the string "postmaster"
         * for the localpart.
         */
        self->sender = InetMailbox_build(SIDF_REQUEST_DEFAULT_LOCALPART, self->helo_domain);
        if (NULL == self->sender) {
            LogNoResource();
            return SIDF_SCORE_SYSERROR;
        }   // end if
        self->eval_by_sender = false;
    } else {
        self->eval_by_sender = true;
    }   // end if
    self->redirect_depth = 0;
    self->include_depth = 0;
    return SidfRequest_checkHost(self, InetMailbox_getDomain(self->sender));
}   // end function : SidfRequest_eval

/**
 * This function sets a IP address to the SidfRequest object via sockaddr structure.
 * The IP address is used as <ip> parameter of check_host function.
 * @param self SidfRequest object.
 * @param af address family. AF_INET for IPv4, AF_INET6 for IPv6.
 * @param addr pointer to the sockaddr_in structure for IPv4,
 *             sockaddr_in6 structure for IPv6.
 * @return true on successful completion, false otherwise.
 *         If af is specified correctly, this function won't fail.
 */
bool
SidfRequest_setIpAddr(SidfRequest *self, int af, const struct sockaddr *addr)
{
    assert(NULL != self);
    assert(NULL != addr);

    self->sin_family = af;
    switch (af) {
    case AF_INET:
        memcpy(&(self->ipaddr.addr4), &(((const struct sockaddr_in *) addr)->sin_addr),
               sizeof(struct in_addr));
        return true;
    case AF_INET6:
        memcpy(&(self->ipaddr.addr6), &(((const struct sockaddr_in6 *) addr)->sin6_addr),
               sizeof(struct in6_addr));
        return true;
    default:
        return false;
    }   // end switch
}   // end function : SidfRequest_setIpAddr

/**
 * 送信者の IP アドレスを文字列表現で SidfRequest にセットする.
 * この IP アドレスは check_host() 関数の引数 <ip> として用いられる.
 * @param self SidfRequest オブジェクト
 * @param af アドレスファミリ. IPv4 の場合は AF_INET, IPv6 の場合は AF_INET6.
 * @param address IP アドレスを表す文字列.
 * @return 成功した場合は true, 失敗した場合は false.
 *         失敗するのはアドレスファミリ af または address が不正な場合のみ.
 */
bool
SidfRequest_setIpAddrString(SidfRequest *self, int af, const char *address)
{
    assert(NULL != self);
    assert(NULL != address);

    self->sin_family = af;
    switch (af) {
    case AF_INET:
        return (1 == inet_pton(AF_INET, address, &(self->ipaddr.addr4))) ? true : false;
    case AF_INET6:
        return (1 == inet_pton(AF_INET6, address, &(self->ipaddr.addr6))) ? true : false;
    default:
        return false;
    }   // end switch
}   // end function : SidfRequest_setIpAddrString

/**
 * 送信者のメールアドレスを SidfRequest にセットする.
 * check_host() 関数の引数 <sender> やマクロの展開の際に用いられる.
 * @return 成功した場合は true, メモリの確保に失敗した場合は false.
 */
bool
SidfRequest_setSender(SidfRequest *self, const InetMailbox *sender)
{
    assert(NULL != self);

    InetMailbox *mailbox = NULL;
    if (NULL != sender) {
        mailbox = InetMailbox_duplicate(sender);
        if (NULL == mailbox) {
            return false;
        }   // end if
    }   // end if

    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
    }   // end if

    self->sender = mailbox;
    return true;
}   // end function : SidfRequest_setSender

/**
 * HELO ドメインを SidfRequest にセットする.
 * <sender> がセットされていない場合に check_host() 関数の引数 <sender> として使用される.
 * また, マクロの展開の際にも用いられる.
 * @return 成功した場合は true, メモリの確保に失敗した場合は false.
 */
bool
SidfRequest_setHeloDomain(SidfRequest *self, const char *domain)
{
    assert(NULL != self);

    char *tmp = NULL;
    if (NULL != domain && NULL == (tmp = strdup(domain))) {
        return false;
    }   // end if
    free(self->helo_domain);
    self->helo_domain = tmp;
    return true;
}   // end function : SidfRequest_setHeloDomain

void
SidfRequest_reset(SidfRequest *self)
{
    assert(NULL != self);
    self->scope = SIDF_RECORD_SCOPE_NULL;
    self->sin_family = 0;
    memset(&(self->ipaddr), 0, sizeof(union ipaddr46));
    if (NULL != self->domain) {
        StrArray_reset(self->domain);
    }   // end if
    self->sender = NULL;
    self->dns_mech_count = 0;
    self->eval_by_sender = true;
    self->local_policy_mode = false;
    if (NULL != self->xbuf) {
        XBuffer_reset(self->xbuf);
    }   // end if
    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
        self->sender = NULL;
    }   // end if
    if (NULL != self->helo_domain) {
        free(self->helo_domain);
        self->helo_domain = NULL;
    }   // end if
    if (NULL != self->explanation) {
        free(self->explanation);
        self->explanation = NULL;
    }   // end if
}   // end function : SidfRequest_reset

void
SidfRequest_free(SidfRequest *self)
{
    assert(NULL != self);
    if (NULL != self->domain) {
        StrArray_free(self->domain);
    }   // end if
    if (NULL != self->xbuf) {
        XBuffer_free(self->xbuf);
    }   // end if
    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
    }   // end if
    if (NULL != self->helo_domain) {
        free(self->helo_domain);
    }   // end if
    if (NULL != self->explanation) {
        free(self->explanation);
    }   // end if
    free(self);
}   // end function : SidfRequest_free

SidfRequest *
SidfRequest_new(const SidfPolicy *policy, DnsResolver *resolver)
{
    SidfRequest *self = (SidfRequest *) malloc(sizeof(SidfRequest));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SidfRequest));
    self->domain = StrArray_new(0);
    if (NULL == self->domain) {
        goto cleanup;
    }   // end if
    self->xbuf = XBuffer_new(0);
    if (NULL == self->xbuf) {
        goto cleanup;
    }   // end if
    self->policy = policy;
    self->resolver = resolver;
    self->eval_by_sender = false;
    self->local_policy_mode = false;
    return self;

  cleanup:
    SidfRequest_free(self);
    return NULL;
}   // end function : SidfRequest_new
