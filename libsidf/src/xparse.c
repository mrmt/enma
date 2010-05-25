/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: xparse.c 195 2008-07-17 05:39:12Z takahiko $
 */
/**
 * @file
 * @brief RFC2045/2821/2822/4871 等で定義されるトークンを解釈する関数群
 * @author takahiko@iij.ad.jp
 */

#include "rcsid.h"
RCSID("$Id: xparse.c 195 2008-07-17 05:39:12Z takahiko $");

#include "xskip.h"
#include "xbuffer.h"
#include "xparse.h"

/*
 * quote の解釈をする必要のない token はこれで読み込める
 */
static int
XParse_something(const char *head, const char *tail, const char **nextp, XBuffer *xbuf,
                 xskip_funcp XSkip_something)
{
    int matchlen = XSkip_something(head, tail, nextp);
    if (0 < matchlen) {
        XBuffer_appendStringN(xbuf, head, matchlen);
    }   // end if
    return matchlen;
}   // end function : XParse_something

int
XParse_char(const char *head, const char *tail, char c, const char **nextp, XBuffer *xbuf)
{
    if (head < tail && *head == c) {
        XBuffer_appendChar(xbuf, *head);
        *nextp = head + 1;
        return 1;
    } else {
        *nextp = head;
        return 0;
    }   // end if
}   // end function : XParse_char

/*
 * [RFC2821 3.2.3.]
 * Runs of FWS, comment or CFWS that occur between lexical tokens in a
 * structured field header are semantically interpreted as a single
 * space character.
 * 
 * @attention lexical tokens の間にあるもののみに適用すること.
 */
int
XParse_cfws(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    int ret = XSkip_cfws(head, tail, nextp);
    if (0 < ret) {
        XBuffer_appendChar(xbuf, ' ');
    }   // end if
    return ret;
}   // end function : XParse_cfws

/*
 * [RFC2821 3.2.3.]
 * Runs of FWS, comment or CFWS that occur between lexical tokens in a
 * structured field header are semantically interpreted as a single
 * space character.
 *
 * @attention lexical tokens の間にあるもののみに適用すること.
 */
static int
XParse_fws(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    int ret = XSkip_fws(head, tail, nextp);
    if (0 < ret) {
        XBuffer_appendChar(xbuf, ' ');
    }   // end if
    return ret;
}   // end function : XParse_fws

/*
 * [RFC2822]
 * quoted-pair = ("\" text) / obs-qp
 */
static int
XParse_quotedPair(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    *nextp = head;
    if (head + 1 < tail && *head == '\\' && IS_TEXT(*(head + 1))) {
        XBuffer_appendChar(xbuf, *(head + 1));
        *nextp += 2;
    }   // end if

    return *nextp - head;
}   // end function : XParse_quotedPair

/*
 * [RFC2822]
 * qcontent = qtext / quoted-pair
 */
static int
XParse_qcontent(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    if (head < tail && IS_QTEXT(*head)) {
        XBuffer_appendChar(xbuf, *head);
        *nextp = head + 1;
        return 1;
    }   // end if

    // *s が qtext でない場合は XParse_quotedPair() にそのまま委譲
    return XParse_quotedPair(head, tail, nextp, xbuf);
}   // end function : XParse_qcontent

/*
 * [RFC2822]
 * dcontent = dtext / quoted-pair
 */
static int
XParse_dcontent(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    if (head < tail && IS_DTEXT(*head)) {
        XBuffer_appendChar(xbuf, *head);
        *nextp = head + 1;
        return 1;
    }   // end if

    // *head が dtext でない場合は XParse_quotedPair() にそのまま委譲
    return XParse_quotedPair(head, tail, nextp, xbuf);
}   // end function : XParse_dcontent

/*
 * [RFC2822]
 * quoted-string = [CFWS]
 *                 DQUOTE *([FWS] qcontent) [FWS] DQUOTE
 *                 [CFWS]
 */
static int
XParse_2822QuotedString(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    xbuffer_savepoint_t savepoint;

    XSkip_cfws(p, tail, &p);
    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if
    savepoint = XBuffer_savepoint(xbuf);
    do {
        XParse_fws(p, tail, &p, xbuf);
    } while (0 < XParse_qcontent(p, tail, &p, xbuf));
    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        XBuffer_rollback(xbuf, savepoint);
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function : XParse_2822QuotedString

/*
 * [RFC2822]
 * domain-literal = [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
 */
static int
XParse_domainLiteral(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    xbuffer_savepoint_t savepoint;

    XSkip_cfws(p, tail, &p);
    savepoint = XBuffer_savepoint(xbuf);
    if (0 >= XSkip_char(p, tail, '[', &p)) {
        *nextp = head;
        return 0;
    }   // end if
    XBuffer_appendChar(xbuf, '[');
    do {
        XParse_fws(p, tail, &p, xbuf);
    } while (0 < XParse_dcontent(p, tail, &p, xbuf));
    if (0 >= XSkip_char(p, tail, ']', &p)) {
        XBuffer_rollback(xbuf, savepoint);
        *nextp = head;
        return 0;
    }   // end if
    XBuffer_appendChar(xbuf, ']');
    XSkip_cfws(p, tail, &p);
    *nextp = p;
    return *nextp - head;
}   // end function : XParse_domainLiteral

/*
 * [RFC2822]
 * dot-atom = [CFWS] dot-atom-text [CFWS]
 */
static int
XParse_dotAtom(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    XSkip_cfws(p, tail, &p);
    if (0 >= XParse_something(p, tail, &p, xbuf, XSkip_dotAtomText)) {
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, nextp);
    return *nextp - head;
}   // end function : XParse_dotAtom

/*
 * [RFC2822]
 * dot-atom = [CFWS] dot-atom-text [CFWS]
 */
static int
XParse_looseDotAtom(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    XSkip_cfws(p, tail, &p);
    if (0 >= XParse_something(p, tail, &p, xbuf, XSkip_looseDotAtomText)) {
        *nextp = head;
        return 0;
    }   // end if
    XSkip_cfws(p, tail, nextp);
    return *nextp - head;
}   // end function : XParse_looseDotAtom

/*
 * [RFC2822]
 * local-part = dot-atom / quoted-string / obs-local-part
 */
int
XParse_2822LocalPart(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *retp;

    if (0 < XParse_looseDotAtom(head, tail, &retp, xbuf)
        || 0 < XParse_2822QuotedString(head, tail, &retp, xbuf)) {
        // dot-atom / quoted-string のいずれかにマッチした場合
        *nextp = retp;
    } else {
        // dot-atom / quoted-string の両方にマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function : XParse_2822LocalPart

/*
 * [RFC2822]
 * domain = dot-atom / domain-literal / obs-domain
 */
int
XParse_2822Domain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *retp;
    if (0 < XParse_dotAtom(head, tail, &retp, xbuf)
        || 0 < XParse_domainLiteral(head, tail, &retp, xbuf)) {
        *nextp = retp;
    } else {
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function : XParse_2822Domain

/*
 * [RFC2821]
 * Dot-string = Atom *("." Atom)
 * Atom       = 1*atext
 */
int
XParse_dotString(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    return XParse_something(head, tail, nextp, xbuf, XSkip_dotString);
}   // end function : XParse_dotString

/*
 * [RFC2821]
 * Dot-string = Atom *("." Atom)
 * Atom       = 1*atext
 */
static int
XParse_looseDotString(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    return XParse_something(head, tail, nextp, xbuf, XSkip_looseDotString);
}   // end function : XParse_looseDotString

/*
 * [RFC2821]
 * Quoted-string = DQUOTE *qcontent DQUOTE
 */
static int
XParse_2821QuotedString(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;

    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if

    // qcontent に少なくとも1文字はマッチすることを確認する
    if (0 >= XParse_qcontent(p, tail, &p, xbuf)) {
        *nextp = head;
        return 0;
    }   // end if

    // 残りの qcontent を読む
    while (0 < XParse_qcontent(p, tail, &p, xbuf));

    if (0 >= XSkip_char(p, tail, '\"', &p)) {
        *nextp = head;
        return 0;
    }   // end if

    *nextp = p;
    return *nextp - head;
}   // end function : XParse_2821QuotedString

/*
 * [RFC2821]
 * Local-part = Dot-string / Quoted-string
 *       ; MAY be case-sensitive
 */
int
XParse_2821LocalPart(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *retp;

    if (0 < XParse_looseDotString(head, tail, &retp, xbuf)
        || 0 < XParse_2821QuotedString(head, tail, &retp, xbuf)) {
        // Dot-string / Quoted-string のいずれかにマッチした場合
        *nextp = retp;
    } else {
        // Dot-string / Quoted-string の両方にマッチしなかった場合
        *nextp = head;
    }   // end if

    return *nextp - head;
}   // end function : XParse_2821LocalPart

/*
 * [RFC2554]
 * xchar    = %x21-2A / %x2C-3C / %x3E-7E
 *            ;; US-ASCII except for "+", "=", SPACE and CTL
 */
static int
XParse_xchar(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    if ((head < tail) && IS_XCHAR(*head)) {
        XBuffer_appendChar(xbuf, *head);
        *nextp = head + 1;
        return 1;
    } else {
        *nextp = head;
        return 0;
    }   // end if
}   // end function : XParse_xchar

#define CHAR2HEX(c) (IS_DIGIT(c) ? (c) - '0' : (c) - 'A' + 0x0a)

/*
 * [RFC2554]
 * DIGIT    = %x30-39            ;; Digits 0-9
 * HEXDIGIT = %x41-46 / DIGIT    ;; hexidecimal digit (uppercase)
 * hexchar  = "+" HEXDIGIT HEXDIGIT
 */
static int
XParse_hexchar(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    if ((head + 2 < tail) && ('+' == *head) && IS_HEXCHAR(*(head + 1)) && IS_HEXCHAR(*(head + 2))) {
        XBuffer_appendChar(xbuf, CHAR2HEX(*(head + 1)) * 0x10 + CHAR2HEX(*(head + 2)));
        *nextp = head + 3;
        return 3;
    } else {
        *nextp = head;
        return 0;
    }   // end if
}   // end function : XParse_hexchar

/*
 * [RFC2554]
 * xtext    = *(xchar / hexchar)
 */
int
XParse_xtext(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    while (0 < XParse_xchar(p, tail, &p, xbuf) || 0 < XParse_hexchar(p, tail, &p, xbuf));
    *nextp = p;
    return *nextp - head;
}   // end function : XParse_xtext

/*
 * [RFC2045]
 * hex-octet := "=" 2(DIGIT / "A" / "B" / "C" / "D" / "E" / "F")
 *              ; Octet must be used for characters > 127, =,
 *              ; SPACEs or TABs at the ends of lines, and is
 *              ; recommended for any character not listed in
 *              ; RFC 2049 as "mail-safe".
 */
static int
XParse_hexOctet(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    if ((head + 2 < tail) && ('=' == *head) && IS_HEXDIG(*(head + 1)) && IS_HEXDIG(*(head + 2))) {
        XBuffer_appendChar(xbuf, CHAR2HEX(*(head + 1)) * 0x10 + CHAR2HEX(*(head + 2)));
        *nextp = head + 3;
        return 3;
    } else {
        *nextp = head;
        return 0;
    }   // end if
}   // end function : XParse_hexOctet

/*
 * [RFC4871]
 * dkim-safe-char =   %x21-3A / %x3C / %x3E-7E
 *               ; '!' - ':', '<', '>' - '~'
 *               ; Characters not listed as "mail-safe" in
 *               ; RFC 2049 are also not recommended.
 */
static int
XParse_dkimSafeChar(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    if ((head < tail) && IS_DKIM_SAFE_CHAR(*head)) {
        XBuffer_appendChar(xbuf, *head);
        *nextp = head + 1;
        return 1;
    } else {
        *nextp = head;
        return 0;
    }   // end if
}   // end function : XParse_dkimSafeChar

/*
 * [RFC4871]
 * dkim-quoted-printable =
 *                    *(FWS / hex-octet / dkim-safe-char)
 *               ; hex-octet is from RFC 2045
 */
int
XParse_dkimQuotedPrintable(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    const char *p = head;
    while (0 < XParse_dkimSafeChar(p, tail, &p, xbuf) || 0 < XParse_hexOctet(p, tail, &p, xbuf)
           || 0 < XSkip_fws(p, tail, &p));
    *nextp = p;
    return *nextp - head;
}   // end function : XParse_dkimQuotedPrintable

/*
 * [RFC4871]
 * selector =   sub-domain *( "." sub-domain )
 */
int
XParse_selector(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    return XParse_something(head, tail, nextp, xbuf, XSkip_selector);
}   // end function : XParse_selector

/*
 * [RFC2821]
 * Domain = (sub-domain 1*("." sub-domain)) / address-literal
 * address-literal = "[" IPv4-address-literal /
 *                       IPv6-address-literal /
 *                       General-address-literal "]"
 *       ; See section 4.1.3
 */
int
XParse_2821Domain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    return XParse_something(head, tail, nextp, xbuf, XSkip_2821Domain);
}   // end function : XParse_2821Domain

/*
 * [RFC3461]
 * real-domain = sub-domain *("." sub-domain)
 */
int
XParse_realDomain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    return XParse_something(head, tail, nextp, xbuf, XSkip_realDomain);
}   // end function : XParse_realDomain

/*
 * [RFC4871]
 * domain-name     = sub-domain 1*("." sub-domain)
 *              ; from RFC 2821 Domain, but excluding address-literal
 */
int
XParse_domainName(const char *head, const char *tail, const char **nextp, XBuffer *xbuf)
{
    return XParse_something(head, tail, nextp, xbuf, XSkip_domainName);
}   // end function : XParse_domainName
