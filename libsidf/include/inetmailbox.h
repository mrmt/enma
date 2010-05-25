/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: inetmailbox.h 194 2008-07-17 05:26:37Z takahiko $
 */

#ifndef __INET_MAILBOX_H__
#define __INET_MAILBOX_H__

#include <stdbool.h>
#include "xbuffer.h"

struct InetMailbox;
typedef struct InetMailbox InetMailbox;

extern InetMailbox *InetMailbox_build(const char *localpart, const char *domain);
extern InetMailbox *InetMailbox_duplicate(const InetMailbox *mailbox);
extern InetMailbox *InetMailbox_buildDkimIdentity(const char *head, const char *tail,
                                                  const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2821Mailbox(const char *head, const char *tail,
                                                 const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2821Path(const char *head, const char *tail,
                                              const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2821ReversePath(const char *head, const char *tail,
                                                     const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2822Mailbox(const char *head, const char *tail,
                                                 const char **nextp, const char **errptr);
extern const char *InetMailbox_getLocalPart(const InetMailbox *self);
extern const char *InetMailbox_getDomain(const InetMailbox *self);
extern bool InetMailbox_isNullAddr(const InetMailbox *self);
extern void InetMailbox_free(InetMailbox *self);
extern size_t InetMailbox_getRawAddrLength(const InetMailbox *self);
extern int InetMailbox_writeRawAddr(const InetMailbox *self, XBuffer *xbuf);
extern bool InetMailbox_isLocalPartQuoted(const InetMailbox *self);
extern int InetMailbox_writeAddrSpec(const InetMailbox *self, XBuffer *xbuf);
extern int InetMailbox_writeMailbox(const InetMailbox *self, XBuffer *xbuf);

extern InetMailbox *InetMailbox_buildSendmailPath(const char *head, const char *tail,
                                                  const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_buildSendmailReversePath(const char *head, const char *tail,
                                                         const char **nextp, const char **errptr);

#endif /* __INET_MAILBOX_H__ */
