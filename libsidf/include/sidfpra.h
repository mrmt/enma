/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfpra.h 49 2008-06-17 00:59:36Z takahiko $
 */

#ifndef __SIDFPRA_H__
#define __SIDFPRA_H__

#include <stdbool.h>
#include "inetmailbox.h"
#include "mailheaders.h"

extern bool SidfPra_extract(const MailHeaders *headers, int *pra_index, InetMailbox **pra_mailbox);

#define SIDF_PRA_RESENT_SENDER_HEADER "Resent-Sender"
#define SIDF_PRA_RESENT_FROM_HEADER "Resent-From"
#define SIDF_PRA_SENDER_HEADER "Sender"
#define SIDF_PRA_FROM_HEADER "From"

#define SIDF_PRA_RECEIVED_HEADER "Received"
#define SIDF_PRA_RETURN_PATH_HEADER "Return-Path"

#endif /* __SIDFPRA_H__ */
