/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: xparse.h 194 2008-07-17 05:26:37Z takahiko $
 */
/**
 * @file
 * @brief RFC2045/2821/2822/4871 等で定義されるトークンを解釈する関数群
 * @author takahiko@iij.ad.jp
 */

#ifndef __XPARSE_H__
#define __XPARSE_H__

#include "xbuffer.h"

typedef int (*xparse_funcp) (const char *, const char *, const char **, XBuffer *);

extern int XParse_char(const char *head, const char *tail, char c, const char **nextp,
                       XBuffer *xbuf);

// RFC 2822
extern int XParse_dotAtomText(const char *head, const char *tail, const char **nextp,
                              XBuffer *xbuf);
extern int XParse_2822LocalPart(const char *head, const char *tail, const char **nextp,
                                XBuffer *xbuf);
extern int XParse_2822Domain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

// RFC 2821
extern int XParse_2821LocalPart(const char *head, const char *tail, const char **nextp,
                                XBuffer *xbuf);
extern int XParse_2821Domain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_dotString(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_cfws(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

// RFC 4871
extern int XParse_selector(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_domainName(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);
extern int XParse_dkimQuotedPrintable(const char *head, const char *tail, const char **nextp,
                                      XBuffer *xbuf);

// RFC 3461
extern int XParse_realDomain(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

// RFC 2554
extern int XParse_xtext(const char *head, const char *tail, const char **nextp, XBuffer *xbuf);

#endif /* __XPARSE_H__ */
