/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfrequest.h 40 2008-05-28 04:49:01Z takahiko $
 */

#ifndef __SIDFREQUEST_H__
#define __SIDFREQUEST_H__

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "xbuffer.h"
#include "strarray.h"
#include "inetmailbox.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "sidfpolicy.h"

typedef struct SidfRequest {
    const SidfPolicy *policy;
    SidfRecordScope scope;      // SPF / SIDF
    short sin_family;
    union ipaddr46 {
        struct in_addr addr4;
        struct in6_addr addr6;
    } ipaddr;
    bool eval_by_sender;        // sender ドメインで SPF の評価をした場合は true, HELO のドメインで評価をした場合は false.
    StrArray *domain;
    char *helo_domain;
    InetMailbox *sender;
    unsigned int dns_mech_count;    // 遭遇した DNS ルックアップを伴うメカニズムの数
    unsigned int redirect_depth;    // 現在の redirect= の深さ
    unsigned int include_depth; // 現在の include の深さ
    bool local_policy_mode;     // ローカルポリシーの評価中は true, 無限ループを防止するための苦肉の策
    XBuffer *xbuf;
    DnsResolver *resolver;      // DNS リゾルバへの参照
    char *explanation;          // fail 時の explanation
} SidfRequest;

extern SidfRequest *SidfRequest_new(const SidfPolicy *policy, DnsResolver *resolver);
extern void SidfRequest_reset(SidfRequest *self);
extern void SidfRequest_free(SidfRequest *self);
extern const char *SidfRequest_getDomain(const SidfRequest *self);
extern SidfScore SidfRequest_eval(SidfRequest *self, SidfRecordScope scope);
extern bool SidfRequest_setSender(SidfRequest *self, const InetMailbox *sender);
extern bool SidfRequest_setHeloDomain(SidfRequest *self, const char *domain);
extern bool SidfRequest_setIpAddr(SidfRequest *self, int af, const struct sockaddr *addr);
extern bool SidfRequest_setIpAddrString(SidfRequest *self, int af, const char *address);

#endif /* __SIDFREQUEST_H__ */
