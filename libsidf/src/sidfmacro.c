/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfmacro.c 348 2008-08-13 15:44:32Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfmacro.c 348 2008-08-13 15:44:32Z takahiko $");

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/nameser.h>

#include "loghandler.h"
#include "eventlogger.h"
#include "ptrop.h"
#include "pstring.h"
#include "xbuffer.h"
#include "xskip.h"
#include "xparse.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "sidf.h"
#include "sidfrecord.h"
#include "sidfrequest.h"
#include "sidfmacro.h"

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#define SIDF_MACRO_DOTTED_INET6ADDRLEN (sizeof("0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f."))

#define IS_MACRO_LITERAL(c) ((0x21 <= (c) && (c) <= 0x7e) && '%' != (c))
#define IS_MACRO_DELIMITER(c) ((c) == '.' || (c) == '-' || (c) == '+' || (c) == ',' || (c) == '/' || (c) == '_' || (c) == '=')

#define SIDF_MACRO_DOMAIN_VALIDATION_PTRRR_MAXNUM 10
#define SIDF_MACRO_ALL_DELIMITERS ".-+,/_="
#define SIDF_MACRO_DEFAULT_DELIMITER '.'
#define SIDF_MACRO_DEFAULT_P_MACRO_VALUE "unknown"
#define SIDF_MACRO_DEFAULT_R_MACRO_VALUE "unknown"

typedef struct SidfMacro {
    SidfMacroLetter letter;
    char delims[sizeof(SIDF_MACRO_ALL_DELIMITERS)];
    // 0 は無制限 (transformer に 0 を指定するのは文法エラーなので, SPF レコード中で 0 が指定されることはない)
    size_t transformer;
    bool reverse;
    bool url_escape;
} SidfMacro;

struct SidfMacroLetterMap {
    const char letter;
    SidfMacroLetter macro;
    bool exp_only;              // "exp" modifier のみで使用可能なマクロの場合は true
};

static const struct SidfMacroLetterMap sidf_macro_letter_table[] = {
    {'s', SIDF_MACRO_S_SENDER, false},
    {'l', SIDF_MACRO_L_SENDER_LOCALPART, false},
    {'o', SIDF_MACRO_O_SENDER_DOMAIN, false},
    {'d', SIDF_MACRO_D_DOMAIN, false},
    {'i', SIDF_MACRO_I_DOTTED_IPADDR, false},
    {'p', SIDF_MACRO_P_IPADDR_VALID_DOMAIN, false},
    {'v', SIDF_MACRO_V_REVADDR_SUFFIX, false},
    {'h', SIDF_MACRO_H_HELO_DOMAIN, false},
    {'c', SIDF_MACRO_C_TEXT_IPADDR, true},
    {'r', SIDF_MACRO_R_CHECKING_DOMAIN, true},
    {'t', SIDF_MACRO_T_TIMESTAMP, true},
    {'\0', SIDF_MACRO_NULL, false},
};

static void
SidfMacro_init(SidfMacro *self)
{
    memset(self, 0, sizeof(SidfMacro));
    self->reverse = false;
    self->url_escape = false;
    self->transformer = 0;
}   // end function : SidfMacro_init

static char *
SidfMacro_dupMailboxAsString(const InetMailbox *mailbox)
{
    const char *localpart = InetMailbox_getLocalPart(mailbox);
    const char *domainpart = InetMailbox_getDomain(mailbox);
    size_t localpart_len = strlen(localpart);
    size_t domainpart_len = strlen(domainpart);
    char *mailaddr = (char *) malloc(localpart_len + domainpart_len + 2);   // 2 は '@' と終端文字
    if (NULL == mailaddr) {
        return NULL;
    }   // end if
    memcpy(mailaddr, localpart, localpart_len);
    mailaddr[localpart_len] = '@';
    memcpy(mailaddr + localpart_len + 1, domainpart, domainpart_len);
    mailaddr[localpart_len + domainpart_len + 1] = '\0';
    return mailaddr;
}   // end function : SidfMacro_dupMailboxAsString

/**
 * @param request SidfRequest object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses don't match.
 *         -1 if DNS error occurred.
 */
static bool
SidfMacro_isValidatedDomainName4(const SidfRequest *request, const char *revdomain)
{
    DnsAResponse *resp;
    int query_stat = DnsResolver_lookupA(request->resolver, revdomain, &resp);
    if (NETDB_SUCCESS != query_stat) {
        return -1;
    }   // end if
    for (size_t m = 0; m < resp->num; ++m) {
        if (0 == memcmp(&(resp->addr[m]), &(request->ipaddr.addr4), NS_INADDRSZ)) {
            DnsAResponse_free(resp);
            return 1;
        }   // end if
    }   // end for
    DnsAResponse_free(resp);
    return 0;
}   // end function : SidfMacro_isValidatedDomainName4

/**
 * @param request SidfRequest object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses don't match.
 *         -1 if DNS error occurred.
 */
static bool
SidfMacro_isValidatedDomainName6(const SidfRequest *request, const char *revdomain)
{
    DnsAaaaResponse *resp;
    int query_stat = DnsResolver_lookupAaaa(request->resolver, revdomain, &resp);
    if (NETDB_SUCCESS != query_stat) {
        return -1;
    }   // end if
    for (size_t m = 0; m < resp->num; ++m) {
        if (0 == memcmp(&(resp->addr[m]), &(request->ipaddr.addr6), NS_IN6ADDRSZ)) {
            DnsAaaaResponse_free(resp);
            return 1;
        }   // end if
    }   // end for
    DnsAaaaResponse_free(resp);
    return 0;
}   // end function : SidfMacro_isValidatedDomainName6

/*
 * @return マクロの値が決定した場合 (IPアドレスが一致した場合 or DNS エラーが発生した場合) は true,
 *         IP アドレスが一致しなかった場合は false.
 */
static bool
SidfMacro_isValidatedDomainName(const SidfRequest *request, const char *revdomain, char **expand)
{
    int ret;
    switch (request->sin_family) {
    case AF_INET:
        ret = SidfMacro_isValidatedDomainName4(request, revdomain);
        break;
    case AF_INET6:
        ret = SidfMacro_isValidatedDomainName6(request, revdomain);
        break;
    default:
        abort();
    }   // end switch
    switch (ret) {
    case 1:
        *expand = strdup(revdomain);
        return true;
    case 0:
        return false;
    case -1:
        *expand = strdup(SIDF_MACRO_DEFAULT_P_MACRO_VALUE);
        return true;
    default:
        abort();
    }   // end switch
}   // end function : SidfMacro_isValidatedDomainName

static char *
SidfMacro_dupValidatedDomainName(const SidfRequest *request, const char *domain)
{
    DnsPtrResponse *respptr;
    int ptrquery_stat =
        DnsResolver_lookupPtr(request->resolver, request->sin_family, &(request->ipaddr), &respptr);
    if (NETDB_SUCCESS != ptrquery_stat) {
        return strdup(SIDF_MACRO_DEFAULT_P_MACRO_VALUE);
    }   // end if
    char *expand = NULL;
    for (size_t n = 0; n < MIN(respptr->num, SIDF_MACRO_DOMAIN_VALIDATION_PTRRR_MAXNUM); ++n) {
        if (InetDomain_isMatch(domain, respptr->domain[n])
            && SidfMacro_isValidatedDomainName(request, respptr->domain[n], &expand)) {
            goto finally;
        }   // end if
    }   // end for
    for (size_t n = 0; n < MIN(respptr->num, SIDF_MACRO_DOMAIN_VALIDATION_PTRRR_MAXNUM); ++n) {
        if (InetDomain_isParent(domain, respptr->domain[n])
            && !InetDomain_isMatch(domain, respptr->domain[n])
            && SidfMacro_isValidatedDomainName(request, respptr->domain[n], &expand)) {
            goto finally;
        }   // end if
    }   // end for
    for (size_t n = 0; n < MIN(respptr->num, SIDF_MACRO_DOMAIN_VALIDATION_PTRRR_MAXNUM); ++n) {
        if (!InetDomain_isParent(domain, respptr->domain[n])
            && SidfMacro_isValidatedDomainName(request, respptr->domain[n], &expand)) {
            goto finally;
        }   // end if
    }   // end for

  finally:
    DnsPtrResponse_free(respptr);
    return expand;
}   // end function : SidfMacro_dupValidatedDomainName

/*
 * p が [0,15] の範囲にあることが前提. それ以外の場合の動作は未定義.
 */
static char
xtoa(unsigned char p)
{
    return p < 0xa ? p + '0' : p + 'a' - 0xa;
}   // end function : xtoa

static char *
SidfMacro_dupDottedIpAddr(const SidfRequest *request)
{
    switch (request->sin_family) {
    case AF_INET:;
        char addrbuf4[INET_ADDRSTRLEN];
        (void) inet_ntop(AF_INET, &(request->ipaddr), addrbuf4, sizeof(addrbuf4));
        return strdup(addrbuf4);
    case AF_INET6:;
        char addrbuf6[SIDF_MACRO_DOTTED_INET6ADDRLEN];
        const unsigned char *rawaddr = (const unsigned char *) &(request->ipaddr.addr6);
        const unsigned char *rawaddr_tail = rawaddr + NS_IN6ADDRSZ;
        char *bufp = addrbuf6;
        for (; rawaddr < rawaddr_tail; ++rawaddr) {
            *(bufp++) = xtoa((*(rawaddr++) & 0xf0) >> 4);
            *(bufp++) = '.';
            *(bufp++) = xtoa(*(rawaddr++) & 0x0f);
            *(bufp++) = '.';
        }   // end for
        return strpdup(addrbuf6, bufp - 1);
        break;
    default:
        abort();
    }   // end switch
}   // end function : SidfMacro_dupDottedIpAddr

static char *
SidfMacro_dupMacroSource(const SidfRequest *request, SidfMacroLetter macro_letter)
{
    switch (macro_letter) {
    case SIDF_MACRO_S_SENDER:
        return SidfMacro_dupMailboxAsString(request->sender);
    case SIDF_MACRO_L_SENDER_LOCALPART:
        return strdup(InetMailbox_getLocalPart(request->sender));
    case SIDF_MACRO_O_SENDER_DOMAIN:
        return strdup(InetMailbox_getDomain(request->sender));
    case SIDF_MACRO_D_DOMAIN:
        return strdup(SidfRequest_getDomain(request));
    case SIDF_MACRO_I_DOTTED_IPADDR:
        return SidfMacro_dupDottedIpAddr(request);
    case SIDF_MACRO_P_IPADDR_VALID_DOMAIN:
        return SidfMacro_dupValidatedDomainName(request, SidfRequest_getDomain(request));
    case SIDF_MACRO_V_REVADDR_SUFFIX:
        return strdup(AF_INET == request->sin_family ? "in-addr" : "ip6");
    case SIDF_MACRO_H_HELO_DOMAIN:
        return strdup(request->helo_domain);
    case SIDF_MACRO_C_TEXT_IPADDR:;
        char addrbuf[INET6_ADDRSTRLEN];
        (void) inet_ntop(request->sin_family, &(request->ipaddr), addrbuf, sizeof(addrbuf));
        return strdup(addrbuf);
    case SIDF_MACRO_R_CHECKING_DOMAIN:
        // 受信した MTA (= SPF の検証をしたホスト) の名前
        return strdup(PTROR(request->policy->checking_domain, SIDF_MACRO_DEFAULT_R_MACRO_VALUE));
    case SIDF_MACRO_T_TIMESTAMP:;
        char timebuf[20];
        snprintf(timebuf, sizeof(timebuf), "%ld", (long) time(NULL));
        return strdup(timebuf);
    default:
        abort();
    }   // end switch
}   // end function : SidfMacro_dupMacroSource

/**
 * 与えられた文字列の領域をセパレーターで区切り, 2次元配列を構築する.
 * s 内の delimstr を NULL で置き換え, 各要素の先頭を示すポインタからなる配列を返す.
 * @param s 区切りたい文字列
 * @param delimstr デリミタとして使う文字を繋げたNULL終端文字列
 * @param num 要素の数を受け取る変数へのポインタ
 * @attention s は上書きされる
 * @attention 返値は使用後に free() を用いて解放すること
 */
static char **
SidfMacro_splitMacroSource(char *s, const char *delimstr, size_t *num)
{
    // 必要な配列のサイズを見積もる
    size_t n;
    char *q;
    for (n = 0, q = s; NULL != (q = strpbrk(q, delimstr)); ++n, ++q);
    // メモリの確保
    char **r = (char **) malloc((n + 2) * sizeof(char *));
    if (NULL == r) {
        return NULL;
    }   // end if

    char *token_tail;
    int idx = 0;
    r[idx] = s;
    while (NULL != (token_tail = strpbrk(r[idx], delimstr))) {
        *token_tail = '\0';
        r[++idx] = token_tail + 1;
    }   // end while
    r[++idx] = NULL;
    *num = idx;
    return r;
}   // end function : SidfMacro_splitMacroSource

static SidfStat
SidfMacro_expandMacro(const SidfMacro *macro, const SidfRequest *request, XBuffer *xbuf)
{
    char *macro_source = SidfMacro_dupMacroSource(request, macro->letter);
    if (NULL == macro_source) {
        LogNoResource();
        return SIDF_STAT_NO_RESOURCE;
    }   // end if
    size_t num;
    char **macro_parts = SidfMacro_splitMacroSource(macro_source, macro->delims, &num);
    if (NULL == macro_parts) {
        free(macro_source);
        LogNoResource();
        return SIDF_STAT_NO_RESOURCE;
    }   // end if

    // reverse が指定されている場合は反転する
    if (macro->reverse) {
        for (size_t n = 0; n < num / 2; ++n) {
            size_t pos = num - n - 1;
            char *tmp = macro_parts[pos];
            macro_parts[pos] = macro_parts[n];
            macro_parts[n] = tmp;
        }   // end for
    }   // end if

    size_t idx = (0 == macro->transformer || num <= macro->transformer)
        ? 0 : num - macro->transformer;
    // TODO: 大文字のマクロは対応する小文字のマクロと同様に展開し, URLエスケープすること
    // NOTE: URL エスケープは explanation レコードのみを対象とすべきではないのか?
    XBuffer_appendString(xbuf, macro_parts[idx]);
    for (++idx; NULL != macro_parts[idx]; ++idx) {
        XBuffer_appendChar(xbuf, '.');
        XBuffer_appendString(xbuf, macro_parts[idx]);
    }   // end for

    free(macro_parts);
    free(macro_source);
    return SIDF_STAT_OK;
}   // end function : SidfMacro_expandMacro

/*
 * [RFC4408]
 * delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
 */
static SidfStat
SidfMacro_parseDelimiterBlock(SidfMacro *macro, const char *head, const char *tail,
                              const char **nextp)
{
    const char *p;
    char *delims_tail = macro->delims;
    for (p = head; p < tail; ++p) {
        const char *delim = strchr(SIDF_MACRO_ALL_DELIMITERS, *p);
        if (NULL == delim) {
            break;
        }   // end if
        // macro->delims に *delim を連結する
        for (char *q = macro->delims; q < delims_tail; ++q) {
            if (*q == *delim) {
                // delimiter が重複指定されている
                LogPermFail("delimiter specified repeatedly in macro-expand: delimiter=%c",
                            (int) *q);
                return SIDF_STAT_RECORD_DELIMITER_DUPLICATED;
            }   // end if
        }   // end if
        *(delims_tail++) = *delim;
    }   // end for

    // delimiter が指定されていない場合はデフォルト値をセット
    if (head == p) {
        *(delims_tail++) = SIDF_MACRO_DEFAULT_DELIMITER;
    }   // end if

    // macro->delims を NULL 終端させる
    *delims_tail = '\0';
    *nextp = p;
    return SIDF_STAT_OK;
}   // end function : SidfMacro_parseDelimiterBlock

/*
 * [RFC4408]
 * macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
 *                    "c" / "r" / "t" / "v"
 */
static SidfStat
SidfMacro_parseMacroLetter(SidfMacro *macro, const char *head, const char *tail, bool exp_record,
                           const char **nextp)
{
    if (head < tail) {
        int lowletter = tolower(*head);
        const struct SidfMacroLetterMap *p;
        for (p = sidf_macro_letter_table; '\0' != p->letter; ++p) {
            if (lowletter == p->letter) {
                if (!exp_record && p->exp_only) {
                    // "exp=" のみで使えるマクロをはじく
                    LogPermFail("macro-letter only for explanation record specified: letter=%c",
                                (int) *head);
                    *nextp = head;
                    return SIDF_STAT_RECORD_UNSUPPORTED_MACRO;
                }   // end if
                macro->letter = p->macro;
                /*
                 * [RFC4408] 8.1.
                 * Uppercased macros expand exactly as their lowercased equivalents, and
                 * are then URL escaped.  URL escaping must be performed for characters
                 * not in the "uric" set, which is defined in [RFC3986].
                 */
                macro->url_escape = isupper(*head) ? true : false;
                *nextp = head + 1;
                return SIDF_STAT_OK;
            }   // end if
        }   // end for
        LogPermFail("undefined macro-letter: letter=%c", (int) *head);
        *nextp = head;
        return SIDF_STAT_RECORD_UNSUPPORTED_MACRO;
    }   // end if
    LogPermFail("macro-letter not specified");
    *nextp = head;
    return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
}   // end function : SidfMacro_parseMacroLetter

/*
 * [RFC4408]
 * transformers     = *DIGIT [ "r" ]
 */
static int
SidfMacro_parseTransformers(SidfMacro *macro, const char *head, const char *tail,
                            const char **nextp)
{
    const char *p = head;
    /*
     * [RFC4408] 8.1.
     * The DIGIT transformer indicates the number of right-hand parts to
     * use, after optional reversal.  If a DIGIT is specified, the value
     * MUST be nonzero.
     */
    // 数字を含まない場合 strptoul は 0 を返す.
    // transformer は 0 の場合無制限を表すので数字を含まない場合のハンドルは (たまたま) 必要ない.
    macro->transformer = strptoul(p, tail, &p);
    macro->reverse = (0 < XSkip_char(p, tail, 'r', &p)) ? true : false;
    *nextp = p;
    return p - head;
}   // end function : SidfMacro_parseTransformers

/*
 * @return SIDF_STAT_OK: 1文字以上マッチ
 *         SIDF_STAT_RECORD_NOT_MATCH: エラーではないがマッチしなかった
 *         SIDF_STAT_RECORD_SYNTAX_VIOLATION: 構文違反
 *         SIDF_STAT_NO_RESOURCE: リソース不足
 *
 * [RFC4408]
 * macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
 *                    / "%%" / "%_" / "%-"
 */
static SidfStat
SidfMacro_parseMacroExpand(const SidfRequest *request, const char *head, const char *tail,
                           bool exp_record, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    if (head + 1 < tail && '%' == *p) {
        switch (*(++p)) {
        case '{':;
            // マクロのパース結果を格納するための用構造体を準備
            SidfMacro macro;
            SidfMacro_init(&macro);
            ++p;

            SidfStat parse_stat = SidfMacro_parseMacroLetter(&macro, p, tail, exp_record, &p);
            if (SIDF_STAT_OK != parse_stat) {
                return parse_stat;
            }   // end if

            SidfMacro_parseTransformers(&macro, p, tail, &p);

            SidfStat delim_stat = SidfMacro_parseDelimiterBlock(&macro, p, tail, &p);
            if (SIDF_STAT_OK != delim_stat) {
                *nextp = head;
                return delim_stat;
            }   // end if

            if (0 < XSkip_char(p, tail, '}', &p)) {
                // ここでやっとマクロとして確定したので展開する
                SidfStat expand_stat = SidfMacro_expandMacro(&macro, request, xbuf);
                if (SIDF_STAT_OK != expand_stat) {
                    *nextp = head;
                    return expand_stat;
                }   // end if
                if (request->policy->macro_expansion_limit < XBuffer_getSize(xbuf)) {
                    LogPermFail("expanded macro too long: limit=%u, length=%u",
                                request->policy->macro_expansion_limit,
                                (unsigned int) XBuffer_getSize(xbuf));
                    *nextp = head;
                    return SIDF_STAT_MALICIOUS_MACRO_EXPANSION;
                }   // end if
                *nextp = p;
                return SIDF_STAT_OK;
            } else {
                LogPermFail("closed parenthesis not found for macro");
                *nextp = head;
                return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if

        case '%':
            /*
             * [RFC4408] 8.1.
             * A literal "%" is expressed by "%%".
             */
            XBuffer_appendChar(xbuf, '%');
            *nextp = head + 2;
            return SIDF_STAT_OK;

        case '_':
            /*
             * [RFC4408] 8.1.
             * "%_" expands to a single " " space.
             */
            XBuffer_appendChar(xbuf, 0x20);
            *nextp = head + 2;
            return SIDF_STAT_OK;

        case '-':
            /*
             * [RFC4408] 8.1.
             * "%-" expands to a URL-encoded space, viz., "%20".
             */
            XBuffer_appendString(xbuf, "%20");
            *nextp = head + 2;
            return SIDF_STAT_OK;

        default:
            // [RFC4408] 8.1.
            //  A '%' character not followed by a '{', '%', '-', or '_' character is
            //  a syntax error.
            LogPermFail("'%%' character not followed by spec-defined character: char=%c", (int) *p);
            *nextp = head;
            return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
        }   // end switch
    }   // end if
    *nextp = head;
    return SIDF_STAT_RECORD_NOT_MATCH;
}   // end function : SidfMacro_parseMacroExpand

/*
 * [RFC4408]
 * macro-literal    = %x21-24 / %x26-7E
 *                    ; visible characters except "%"
 */
static int
SidfMacro_parseMacroLiteralBlock(const char *head, const char *tail, const char **nextp,
                                 XBuffer *xbuf)
{
    const char *p;
    for (p = head; p < tail && IS_MACRO_LITERAL(*p); ++p);
    *nextp = p;
    int matchlen = *nextp - head;
    if (0 < matchlen) {
        XBuffer_appendStringN(xbuf, head, matchlen);
    }   // end if
    return matchlen;
}   // end function : SidfMacro_parseMacroLiteralBlock

/*
 * [RFC4408]
 * macro-string     = *( macro-expand / macro-literal )
 */
static SidfStat
SidfMacro_parseMacroString(const SidfRequest *request, const char *head, const char *tail,
                           bool exp_record, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    while (true) {
        (void) SidfMacro_parseMacroLiteralBlock(p, tail, &p, xbuf);
        SidfStat macro_stat = SidfMacro_parseMacroExpand(request, p, tail, exp_record, &p, xbuf);
        switch (macro_stat) {
        case SIDF_STAT_OK:
            break;
        case SIDF_STAT_RECORD_NOT_MATCH:
            *nextp = p;
            return (0 < p - head) ? SIDF_STAT_OK : SIDF_STAT_RECORD_NOT_MATCH;
        default:
            *nextp = head;
            return macro_stat;
        }   // end switch
    }   // end while
}   // end function : SidfMacro_parseMacroString

/*
 * [RFC4408]
 * explain-string   = *( macro-string / SP )
 */
SidfStat
SidfMacro_parseExplainString(const SidfRequest *request, const char *head, const char *tail,
                             const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    while (true) {
        int sp_match = XParse_char(p, tail, ' ', &p, xbuf);
        SidfStat parse_stat = SidfMacro_parseMacroString(request, p, tail, true, &p, xbuf);
        switch (parse_stat) {
        case SIDF_STAT_OK:
            break;
        case SIDF_STAT_RECORD_NOT_MATCH:
            if (0 == sp_match) {
                *nextp = p;
                return 0 < *nextp - head ? SIDF_STAT_OK : SIDF_STAT_RECORD_NOT_MATCH;
            }   // end if
            break;
        default:
            *nextp = head;
            return parse_stat;
        }   // end switch
    }   // end while
}   // end function : SidfMacro_parseExplainString

/*
 * [RFC4408]
 * toplabel         = ( *alphanum ALPHA *alphanum ) /
 *                    ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
 *                    ; LDH rule plus additional TLD restrictions
 *                    ; (see [RFC3696], Section 2)
 */
static int
SidfMacro_skipTopLabel(const char *head, const char *tail, const char **nextp)
{
    // ABNF をよく読むと　2821 sub-domain と同じ
    return XSkip_subDomain(head, tail, nextp);
}   // end function : SidfMacro_skipTopLabel

/*
 * [RFC4408]
 * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
 */
static SidfStat
SidfMacro_parseDomainEnd(const SidfRequest *request, const char *head, const char *tail,
                         const char **nextp, XBuffer *xbuf)
{
    const char *p;
    if (0 < XSkip_char(head, tail, '.', &p) && 0 < SidfMacro_skipTopLabel(p, tail, &p)) {
        XSkip_char(p, tail, '.', nextp);
        XBuffer_appendStringN(xbuf, head, *nextp - head);
        return SIDF_STAT_OK;
    }   // end if
    return SidfMacro_parseMacroExpand(request, head, tail, false, nextp, xbuf);
}   // end function : SidfMacro_parseDomainEnd

/*
 * [RFC4408]
 * domain-spec      = macro-string domain-end
 * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
 * toplabel は RFC2821 の sub-domain に等しい
 *
 * domain-spec      = *( macro-expand / macro-literal ) ( ( "." sub-domain [ "." ] ) / macro-expand )
 */
SidfStat
SidfMacro_parseDomainSpec(const SidfRequest *request, const char *head, const char *tail,
                          const char **nextp, XBuffer *xbuf)
// NOTE: macro-string 中の macro-literal がなんでも食っちゃう. domain-end を判別できないのが一番ツライ
// NOTE: 少なくとも "/", "=", ":" は macro-string から抜くべき.
// label = alphanum / "-" / "_" くらいでいいと思う
// あるいは '.' を目印に sub-domain を先に評価するとか
// [RFC4408] 4.6.1
// Modifiers always contain an equals ('=') character immediately after
// the name, and before any ":" or "/" characters that may be part of
// the macro-string.
//
// Terms that do not contain any of "=", ":", or "/" are mechanisms, as
// defined in Section 5.
{
    const char *p = head;

    SidfStat parse_stat = SidfMacro_parseMacroString(request, p, tail, false, &p, xbuf);
    if (SIDF_STAT_OK != parse_stat) {
        *nextp = head;
        return parse_stat;
    }   // end if

    parse_stat = SidfMacro_parseDomainEnd(request, p, tail, &p, xbuf);
    if (SIDF_STAT_OK == parse_stat || SIDF_STAT_RECORD_NOT_MATCH == parse_stat) {
        // RFC4408 の ABNF がダメダメなので, 前からパースすると macro-string が domain-end を喰っちゃう.
        // よって文法的に正しくても domain-end にはマッチしない場合もある.
        parse_stat = SIDF_STAT_OK;
        *nextp = p;
    } else {
        *nextp = head;
    }   // end if
    return parse_stat;
}   // end function : SidfMacro_parseDomainSpec
