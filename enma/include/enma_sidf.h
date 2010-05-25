/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id:enma_config.h 154 2008-07-07 08:16:11Z tsuruda $
 */

#ifndef __ENMA_SIDF_H__
#define __ENMA_SIDF_H__

#include <stdbool.h>
#include <sys/socket.h>

#include "inetmailbox.h"
#include "mailheaders.h"
#include "dnsresolv.h"
#include "sidfpolicy.h"
#include "authresult.h"

extern bool EnmaSpf_evaluate(SidfPolicy *policy, DnsResolver *resolver, AuthResult *authresult,
                             const struct sockaddr *hostaddr, const char *ipaddr,
                             const char *helohost, const char *raw_envfrom,
                             const InetMailbox *envfrom, bool explog);
extern bool EnmaSidf_evaluate(SidfPolicy *policy, DnsResolver *resolver, AuthResult *authresult,
                              const struct sockaddr *hostaddr, const char *ipaddr,
                              const char *helohost, const MailHeaders *headers, bool explog);

#endif
