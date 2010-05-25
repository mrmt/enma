/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: inetmailbox.c 195 2008-07-17 05:39:12Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: inetmailbox.c 195 2008-07-17 05:39:12Z takahiko $");

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ptrop.h"
#include "xskip.h"
#include "xparse.h"
#include "xbuffer.h"
#include "inetmailbox.h"

struct InetMailbox {
    char *localpart;
    char *domain;
    char buf[];
};

/**
 * InetMailbox オブジェクトの構築
 * @return 空の InetMailbox オブジェクト
 */
static InetMailbox *
InetMailbox_new(size_t buflen)
{
    InetMailbox *self = (InetMailbox *) malloc(sizeof(InetMailbox) + buflen);
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(InetMailbox));   // 0 で埋めるのは先頭部分だけで十分

    return self;
}   // end function : InetMailbox_new

/**
 * InetMailbox オブジェクトの解放
 * @param self 解放する InetMailbox オブジェクト
 */
void
InetMailbox_free(InetMailbox *self)
{
    assert(NULL != self);
    free(self);
}   // end function : InetMailbox_free

const char *
InetMailbox_getLocalPart(const InetMailbox *self)
{
    return self->localpart;
}   // end function : InetMailbox_getLocalPart

const char *
InetMailbox_getDomain(const InetMailbox *self)
{
    return self->domain;
}   // end function : InetMailbox_getDomain

/*
 * いわゆる "<>" かどうかを調べる.
 */
bool
InetMailbox_isNullAddr(const InetMailbox *self)
{
    return (NULL != self->localpart) && ('\0' == *(self->localpart))
        && ('\0' == *(self->domain));
}   // end function : InetMailbox_isNullAddr

/*
 * @param errptr エラー情報を返す. メモリの確保に失敗した場合は NULL をセットする.
 *               parse に失敗した場合は失敗した位置へのポインタを返す.
 *
 * addr-spec = local-part "@" domain
 */
static InetMailbox *
InetMailbox_parse(const char *head, const char *tail, const char **nextp,
                  xparse_funcp xparse_localpart, bool requireLocalPart,
                  xparse_funcp xparse_domain, bool requireDomain, const char **errptr)
{
    const char *p = head;

    XBuffer *xbuf = XBuffer_new(tail - head);
    if (NULL == xbuf) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    if (0 >= xparse_localpart(p, tail, &p, xbuf) && requireLocalPart) {
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    if (0 != XBuffer_status(xbuf)) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    size_t localpartlen = XBuffer_getSize(xbuf);
    if (0 > XBuffer_appendChar(xbuf, '\0')) {   // local-part と domain の区切りの NULL 文字
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    if (0 >= XSkip_char(p, tail, '@', &p)) {
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    if (0 >= xparse_domain(p, tail, &p, xbuf) && requireDomain) {
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    if (0 != XBuffer_status(xbuf)) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    size_t xbuflen = XBuffer_getSize(xbuf);
    InetMailbox *self = InetMailbox_new(xbuflen + 1);   // 1 は NULL 文字の分
    if (NULL == self) {
        SETDEREF(errptr, NULL);
        goto cleanup;
    }   // end if

    memcpy(self->buf, XBuffer_getBytes(xbuf), xbuflen);
    self->buf[xbuflen] = '\0';
    self->localpart = self->buf;
    self->domain = self->buf + localpartlen + 1;

    XBuffer_free(xbuf);
    *nextp = p;
    SETDEREF(errptr, NULL);
    return self;

  cleanup:
    if (NULL != xbuf) {
        XBuffer_free(xbuf);
    }   // end if
    *nextp = head;
    return NULL;
}   // end function : InetMailbox_parse

/*
 * [RFC2822]
 * mailbox      = name-addr / addr-spec
 * mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list
 * name-addr    = [display-name] angle-addr
 * angle-addr   = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
 * display-name = phrase
 * addr-spec    = local-part "@" domain
 */
InetMailbox *
InetMailbox_build2822Mailbox(const char *head, const char *tail, const char **nextp,
                             const char **errptr)
{
    bool guessNameaddr;         // mailbox = name-addr を想定している ('<' が見つかった) 場合に真

    // ABNF をまとめると
    // mailbox = ([phrase] [CFWS] "<" addr-spec ">" [CFWS]) / addr-spec
    // 判断基準は '<', '>' の存在だけ

    // display-name を捨てて addr-spec にたどり着くために
    // name-addr にマッチするか調べる
    const char *p = head;
    XSkip_phrase(p, tail, &p);  // display-name の実体
    XSkip_cfws(p, tail, &p);
    if (0 < XSkip_char(p, tail, '<', &p)) {
        // mailbox = name-addr
        guessNameaddr = true;
    } else {
        // mailbox = addr-spec
        p = head;
        guessNameaddr = false;
    }   // end if

    InetMailbox *self =
        InetMailbox_parse(p, tail, &p, XParse_2822LocalPart, true, XParse_2822Domain, true, errptr);
    if (NULL == self) {
        goto cleanup;
    }   // end if

    if (guessNameaddr) {
        // mailbox = name-addr なのに '>' が存在しない
        if (0 >= XSkip_char(p, tail, '>', &p)) {
            SETDEREF(errptr, p);
            goto cleanup;
        }   // end if
        XSkip_cfws(p, tail, &p);
    }   // end if

    *nextp = p;
    return self;

  cleanup:
    if (NULL != self) {
        InetMailbox_free(self);
    }   // end if
    *nextp = head;
    return NULL;
}   // end function : InetMailbox_build2822Mailbox

/*
 * @attention source route は取り扱わない.
 *
 * [RFC2821]
 * Mailbox = Local-part "@" Domain
 * Local-part = Dot-string / Quoted-string
 *       ; MAY be case-sensitive
 */
InetMailbox *
InetMailbox_build2821Mailbox(const char *head, const char *tail, const char **nextp,
                             const char **errptr)
{
    const char *p = head;
    InetMailbox *self =
        InetMailbox_parse(p, tail, &p, XParse_2821LocalPart, true, XParse_2821Domain, true, errptr);
    if (NULL == self) {
        *nextp = head;
        return NULL;
    }   // end if

    *nextp = p;
    return self;
}   // end function : InetMailbox_build2821Mailbox

/*
 * @attention source route は取り扱わない.
 *
 * [RFC2821]
 * Reverse-path = Path
 * Forward-path = Path
 * Path = "<" [ A-d-l ":" ] Mailbox ">"
 * A-d-l = At-domain *( "," A-d-l )
 *       ; Note that this form, the so-called "source route",
 *       ; MUST BE accepted, SHOULD NOT be generated, and SHOULD be
 *       ; ignored.
 * At-domain = "@" domain
 * Mailbox = Local-part "@" Domain
 * Local-part = Dot-string / Quoted-string
 *       ; MAY be case-sensitive
 */
static InetMailbox *
InetMailbox_build2821PathImpl(const char *head, const char *tail, const char **nextp,
                              bool require_bracket, const char **errptr)
{
    InetMailbox *self = NULL;
    bool have_bracket = false;

    const char *p = head;
    if (0 < XSkip_char(p, tail, '<', &p)) {
        have_bracket = true;
    } else {
        if (require_bracket) {
            SETDEREF(errptr, p);
            goto cleanup;
        }   // end if
    }   // end if

    self =
        InetMailbox_parse(p, tail, &p, XParse_2821LocalPart, true, XParse_2821Domain, true, errptr);
    if (NULL == self) {
        goto cleanup;
    }   // end if

    if (have_bracket && 0 >= XSkip_char(p, tail, '>', &p)) {
        // "<" で始まっているのに対応する ">" が見つからなかった場合
        SETDEREF(errptr, p);
        goto cleanup;
    }   // end if

    *nextp = p;
    return self;

  cleanup:
    if (NULL != self) {
        InetMailbox_free(self);
    }   // end if
    *nextp = head;
    return NULL;
}   // end function : InetMailbox_build2821PathImpl

InetMailbox *
InetMailbox_build2821Path(const char *head, const char *tail, const char **nextp,
                          const char **errptr)
{
    return InetMailbox_build2821PathImpl(head, tail, nextp, true, errptr);
}   // end function : InetMailbox_build2821Path

/*
 * sendmail の envelope from/rcpt に "<", ">" なしのメールアドレスを受け付ける実装に対応しつつ InetMailbox オブジェクトを構築する.
 * "<>" は受け付けない.
 */
InetMailbox *
InetMailbox_buildSendmailPath(const char *head, const char *tail, const char **nextp,
                              const char **errptr)
{
    return InetMailbox_build2821PathImpl(head, tail, nextp, false, errptr);
}   // end function : InetMailbox_buildSendmailPath

static InetMailbox *
InetMailbox_build2821ReversePathImpl(const char *head, const char *tail, const char **nextp,
                                     bool require_bracket, const char **errptr)
{
    if (0 < XSkip_string(head, tail, "<>", nextp)) {
        // "<>" 用
        SETDEREF(errptr, NULL);
        return InetMailbox_build("", "");
    }   // end if

    return InetMailbox_build2821PathImpl(head, tail, nextp, require_bracket, errptr);
}   // end function : InetMailbox_build2821ReversePathImpl

/*
 * @attention 厳密には Reverse-path には "<>" は含まれない
 */
InetMailbox *
InetMailbox_build2821ReversePath(const char *head, const char *tail, const char **nextp,
                                 const char **errptr)
{
    return InetMailbox_build2821ReversePathImpl(head, tail, nextp, true, errptr);
}   // end function : InetMailbox_build2821ReversePath

/*
 * sendmail の envelope from/rcpt に "<", ">" なしのメールアドレスを受け付ける実装に対応しつつ InetMailbox オブジェクトを構築する.
 * "<>" を受け付ける. 
 */
InetMailbox *
InetMailbox_buildSendmailReversePath(const char *head, const char *tail, const char **nextp,
                                     const char **errptr)
{
    return InetMailbox_build2821ReversePathImpl(head, tail, nextp, false, errptr);
}   // end function : InetMailbox_buildSendmailReversePath

/*
 * [RFC4871]
 * sig-i-tag =   %x69 [FWS] "=" [FWS] [ Local-part ] "@" domain-name
 */
InetMailbox *
InetMailbox_buildDkimIdentity(const char *head, const char *tail, const char **nextp,
                              const char **errptr)
{
    return InetMailbox_parse(head, tail, nextp, XParse_2821LocalPart, false, XParse_domainName,
                             true, errptr);
}   // end function : InetMailbox_buildDkimIdentity

/**
 * local-part と domain を指定して InetMailbox オブジェクトを構築する
 * @param localpart local-part を指定する. NULL は許されない.
 * @param domain domain を指定する. NULL は許されない.
 * @return 構築した InetMailbox オブジェクト. 失敗した場合は NULL
 */
InetMailbox *
InetMailbox_build(const char *localpart, const char *domain)
{
    assert(NULL != localpart);
    assert(NULL != domain);

    size_t localpartlen = strlen(localpart);
    size_t domainlen = strlen(domain);

    InetMailbox *self = InetMailbox_new(localpartlen + domainlen + 2);
    if (NULL == self) {
        return NULL;
    }   // end if

    memcpy(self->buf, localpart, localpartlen);
    self->buf[localpartlen] = '\0';
    memcpy(self->buf + localpartlen + 1, domain, domainlen);
    self->buf[localpartlen + 1 + domainlen] = '\0';
    self->localpart = self->buf;
    self->domain = self->buf + localpartlen + 1;

    return self;
}   // end function : InetMailbox_build

/**
 * InetMailbox オブジェクトを複製する.
 * @param mailbox 複製したい InetMailbox オブジェクト.
 * @return 構築した InetMailbox オブジェクト. 失敗した場合は NULL.
 */
InetMailbox *
InetMailbox_duplicate(const InetMailbox *mailbox)
{
    assert(NULL != mailbox);
    return InetMailbox_build(mailbox->localpart, mailbox->domain);
}   // end function : InetMailbox_duplicate

/*
 * local-part + "@" + domain の長さを返す.
 */
size_t
InetMailbox_getRawAddrLength(const InetMailbox *self)
{
    assert(NULL != self);
    return strlen(self->localpart) + strlen(self->domain) + 1;  // 1 は '@' の分
}   // end function : InetMailbox_getRawAddrLength

/*
 * @return 成功した場合は 0, エラーが発生した場合はエラーコード
 */
int
InetMailbox_writeRawAddr(const InetMailbox *self, XBuffer *xbuf)
{
    assert(NULL != self);
    assert(NULL != xbuf);
    XBuffer_appendString(xbuf, self->localpart);
    XBuffer_appendChar(xbuf, '@');
    XBuffer_appendString(xbuf, self->domain);
    return XBuffer_status(xbuf);
}   // end function : InetMailbox_writeRawAddr

/*
 * localpart が dot-atom-text にマッチするかを調べる.
 * マッチしない場合は, ヘッダに書き出す際には localpart を DQUOTE で括る必要がある.
 */
bool
InetMailbox_isLocalPartQuoted(const InetMailbox *self)
{
    assert(NULL != self);
    assert(NULL != self->localpart);
    const char *nextp = NULL;
    const char *localparttail = STRTAIL(self->localpart);
    XSkip_looseDotAtomText(self->localpart, localparttail, &nextp);
    return nextp < localparttail;
}   // end function : InetMailbox_isLocalPartQuoted

/*
 * @attention "<>" は扱わない. "<>" も扱いたい場合は InetMailbox_writeMailbox() を使用のこと.
 */
int
InetMailbox_writeAddrSpec(const InetMailbox *self, XBuffer *xbuf)
// localpart に NULL, CR, LF は含まれないという前提
{
    assert(NULL != self);
    assert(NULL != xbuf);

    const char *localparttail = STRTAIL(self->localpart);
    bool quoted = InetMailbox_isLocalPartQuoted(self);

    if (quoted) {
        XBuffer_appendChar(xbuf, '"');
    }   // end if

    for (const char *p = self->localpart; p < localparttail; ++p) {
        switch (*p) {
        case '\r':
        case '\n':
            // quoted-pair にもならない, そもそも含まれていてはならない
            // abort();
            break;

        case ' ':
        case '"':
        case '\\':
        case '\t':
            // text にはマッチするが qtext にはマッチしない文字を quote する
            XBuffer_appendChar(xbuf, '\\');
            break;

        default:
            // do nothing
            break;
        }   // end switch
        XBuffer_appendChar(xbuf, *p);
    }   // end for

    if (quoted) {
        XBuffer_appendChar(xbuf, '"');
    }   // end if

    XBuffer_appendChar(xbuf, '@');
    XBuffer_appendString(xbuf, self->domain);
    return XBuffer_status(xbuf);
}   // end function : InetMailbox_writeAddrSpec

int
InetMailbox_writeMailbox(const InetMailbox *self, XBuffer *xbuf)
// localpart に NULL, CR, LF は含まれないという前提
{
    if (InetMailbox_isNullAddr(self)) {
        XBuffer_appendString(xbuf, "<>");
        return XBuffer_status(xbuf);
    } else {
        return InetMailbox_writeAddrSpec(self, xbuf);
    }   // end if
}   // end function : InetMailbox_writeMailbox
