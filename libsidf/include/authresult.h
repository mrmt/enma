/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: authresult.h 370 2008-08-15 14:26:58Z takahiko $
 */

#ifndef __AUTH_RESULT_H__
#define __AUTH_RESULT_H__

#include <stdbool.h>
#include "foldstring.h"
#include "inetmailbox.h"

/// Authentication-Results ヘッダのフィールド名
#define AUTHRESULTSHDR	"Authentication-Results"

// method
#define AUTHRES_METHOD_AUTH	"auth"
#define AUTHRES_METHOD_DOMAINKEYS	"domainkeys"
#define AUTHRES_METHOD_IPREV	"iprev"
#define AUTHRES_METHOD_SENDERID	"senderid"
#define AUTHRES_METHOD_SPF	"spf"

// ptype
#define AUTHRES_PTYPE_NULL	""
#define AUTHRES_PTYPE_SMTP	"smtp"
#define AUTHRES_PTYPE_HEADER	"header"
#define AUTHRES_PTYPE_BODY	"body"
#define AUTHRES_PTYPE_POLICY	"policy"

// property
#define AUTHRES_PROPERTY_NULL	""
#define AUTHRES_PROPERTY_AUTH	"auth"
#define AUTHRES_PROPERTY_D	"d"
#define AUTHRES_PROPERTY_I	"i"
#define AUTHRES_PROPERTY_FROM	"from"
#define AUTHRES_PROPERTY_SENDER	"sender"
#define AUTHRES_PROPERTY_MAILFROM	"mailfrom"
#define AUTHRES_PROPERTY_HELO	"helo"


typedef FoldString AuthResult;

extern const char *AuthResult_getFieldName(void);
extern AuthResult *AuthResult_new(void);
extern bool AuthResult_appendAuthServer(AuthResult *self, const char *authserv_id);
extern bool AuthResult_appendAuthServer(AuthResult *self, const char *authserv_id);
extern bool AuthResult_appendMethodSpec(AuthResult *self, const char *method, const char *result);
extern bool AuthResult_appendPropSpecWithToken(AuthResult *self, const char *ptype,
                                               const char *property, const char *value);
extern bool AuthResult_appendPropSpecWithAddrSpec(AuthResult *self, const char *ptype,
                                                  const char *property, const InetMailbox *mailbox);
extern bool AuthResult_compareAuthservId(const char *field, const char *hostname);

#define AuthResult_free(a)	FoldString_free(a)
#define AuthResult_reset(a)	FoldString_reset(a)
#define AuthResult_status(a)	FoldString_status(a)
#define AuthResult_getFieldBody(a)	FoldString_getString(a)

#endif /*__AUTH_RESULT_H__*/
