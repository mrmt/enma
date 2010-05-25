/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: authresult.c 373 2008-08-18 01:52:18Z takahiko $
 */
/**
 * @file
 * @brief Authenticatoin-Results ヘッダ生成クラス
 * @author takahiko@iij.ad.jp
 * @version $Id: authresult.c 373 2008-08-18 01:52:18Z takahiko $
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "loghandler.h"
#include "ptrop.h"
#include "posixaux.h"
#include "xbuffer.h"
#include "foldstring.h"
#include "xskip.h"
#include "inetmailbox.h"
#include "authresult.h"

#define AUTHRES_WIDTH	78

/*
 * [draft-kucherawy-sender-auth-header-15 2.2.]
 * header = "Authentication-Results:" [CFWS] authserv-id
 *          [ CFWS version ]
 *          ( [CFWS] ";" [CFWS] "none" / 1*resinfo ) [CFWS] CRLF
 * authserv-id = dot-atom-text
 * version = 1*DIGIT [CFWS]
 * resinfo = [CFWS] ";" methodspec [ CFWS reasonspec ]
 *           *( CFWS propspec )
 * methodspec = [CFWS] method [CFWS] "=" [CFWS] result
 * reasonspec = "reason" [CFWS] "=" [CFWS] value
 * propspec = ptype [CFWS] "." [CFWS] property [CFWS] "=" pvalue
 * method = token [ [CFWS] "/" [CFWS] version ]
 * result = token
 * ptype = "smtp" / "header" / "body" / "policy"
 * property = token
 * pvalue = [CFWS] ( token / addr-spec ) [CFWS]
 */

const char *
AuthResult_getFieldName(void)
{
    return AUTHRESULTSHDR;
}   // end function : AuthResult_getFieldName

AuthResult *
AuthResult_new(void)
{
    AuthResult *self = FoldString_new(AUTHRES_WIDTH);
    if (NULL == self) {
        return NULL;
    }   // end if

    // 1 行あたり 78 byte を越えないように頑張る
    FoldString_setLineLengthLimits(self, AUTHRES_WIDTH);
    // folding の際に CR は使用しない
    FoldString_setFoldingCR(self, false);
    // "Authentication-Results: " の分のスペースを確保
    FoldString_consumeLineSpace(self, strlen(AUTHRESULTSHDR ": "));

    return self;
}   // end function : AuthResult_new

bool
AuthResult_appendAuthServer(AuthResult *self, const char *authserv_id)
{
    // authserv-id
    return 0 == FoldString_appendBlock(self, true, authserv_id) ? true : false;
}   // end function : AuthResult_appendAuthServer

bool
AuthResult_appendMethodSpec(AuthResult *self, const char *method, const char *result)
{
    // methodspec
    (void) FoldString_appendChar(self, false, ';');
    (void) FoldString_appendFormatBlock(self, true, " %s=%s", method, result);
    return EOK == FoldString_status(self) ? true : false;
}   // end function : AuthResult_appendMethodSpec

bool
AuthResult_appendPropSpecWithToken(AuthResult *self, const char *ptype, const char *property,
                                   const char *value)
{
    // propspec
    return 0 == FoldString_appendFormatBlock(self, true, " %s.%s=%s", ptype, property,
                                             value) ? true : false;
}   // end function : AuthResult_appendPropSpecWithToken

bool
AuthResult_appendPropSpecWithAddrSpec(AuthResult *self, const char *ptype, const char *property,
                                      const InetMailbox *mailbox)
{
    assert(NULL != mailbox);

    XBuffer *buf = XBuffer_new(256);
    if (NULL == buf) {
        return false;
    }   // end if
    int write_stat = InetMailbox_writeMailbox(mailbox, buf);
    if (EOK != write_stat) {
        goto cleanup;
    }   // end if

    bool append_stat =
        AuthResult_appendPropSpecWithToken(self, ptype, property, XBuffer_getString(buf));
    XBuffer_free(buf);
    return append_stat;

  cleanup:
    XBuffer_free(buf);
    return false;
}   // end function : AuthResult_appendPropSpecWithMailbox

/**
 * Authentication-Results ヘッダのフィールド値に含まれる authserv-id が hostname に一致するか調べる.
 * @param headerv Authentication-Results ヘッダの値部分
 * @param auth_hostname 削除対象の条件とする hostname
 * @return ホスト名が一致した場合は真, 一致しなかった場合は偽
 */
bool
AuthResult_compareAuthservId(const char *field, const char *hostname)
{
    // Authentication-Results 全体の終端
    const char *fieldtail = STRTAIL(field);

    // Authentication-Results ヘッダから authserv-id を抜き出す
    const char *hosthead, *hosttail;
    (void) XSkip_cfws(field, fieldtail, &hosthead);
    if (0 >= XSkip_dotAtomText(hosthead, fieldtail, &hosttail)) {
        // authserv-id が dot-atom-text ではない
        LogDebug("authserv-id doesn't seem dot-atom-text: field=%s", field);
        return false;
    }   // end if

    // dot-atom-text の後で単語が切れていることを確認する.
    // 古い Authentication-Results のヘッダの仕様では authserv_id の後は CFWS だったので,
    // authserv_id の後に CFWS がある場合は ';' がなくても authserv_id であると見なす.
    const char *tail;
    if (hosttail == fieldtail || 0 < XSkip_cfws(hosttail, fieldtail, &tail)
        || 0 < XSkip_char(tail, fieldtail, ';', &tail)) {
        // Authentication-Results ヘッダから抜き出した authserv-id と hostname を比較する.
        const char *nextp;
        XSkip_casestring(hosthead, hosttail, hostname, &nextp);
        return hosttail == nextp ? true : false;
    }   // end if

    LogDebug("authserv-id doesn't seem dot-atom-text: field=%s", field);
    return false;
}   // end function : AuthResult_compareAuthservId
