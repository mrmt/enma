/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: mailheaders.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __MAIL_HEADERS_H__
#define __MAIL_HEADERS_H__

#include <sys/types.h>
#include <stdbool.h>
#include "strpairarray.h"

typedef StrPairArray MailHeaders;

extern MailHeaders *MailHeaders_new(size_t size);
extern int MailHeaders_getHeaderIndex(const MailHeaders *self, const char *fieldname,
                                      bool *multiple);
extern int MailHeaders_getNonEmptyHeaderIndex(const MailHeaders *self, const char *fieldname,
                                              bool *multiple);

#define MailHeaders_free(a)	StrPairArray_free(a)
#define MailHeaders_getCount(a)	StrPairArray_getCount(a)
#define MailHeaders_get(a, b, c, d)	StrPairArray_get(a, b, c, d)
#define MailHeaders_append(a, b, c)	StrPairArray_append(a, b, c)
#define MailHeaders_reset(a)	StrPairArray_reset(a)

#endif /* __MAIL_HEADERS_H__ */
