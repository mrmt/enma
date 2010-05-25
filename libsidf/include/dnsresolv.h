/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dnsresolv.h 345 2008-08-13 10:13:01Z takahiko $
 */

#ifndef __DNSRESOLV_H__
#define __DNSRESOLV_H__

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <resolv.h>
#include <arpa/nameser.h>

#ifndef NS_MAXMSG
#define NS_MAXMSG NS_PACKETSZ
#endif

typedef struct DnsResolver {
    struct __res_state resolver;
    ns_msg msghanlde;
    int resolv_h_errno;
    int resolv_errno;
    int msglen;
    unsigned char msgbuf[NS_MAXMSG];
} DnsResolver;

typedef struct DnsResponse DnsResponse;

typedef struct DnsAResponse {
    size_t num;
    struct in_addr addr[];
} DnsAResponse;

typedef struct DnsAaaaResponse {
    size_t num;
    struct in6_addr addr[];
} DnsAaaaResponse;

typedef struct DnsPtrResponse {
    size_t num;
    char *domain[];
} DnsPtrResponse;

struct DnsTxtResponse {
    size_t num;
    char *data[];
};

typedef struct DnsTxtResponse DnsTxtResponse;
typedef struct DnsTxtResponse DnsSpfResponse;

struct mxentry {
    unsigned short preference;
    char domain[];
};

typedef struct DnsMxResponse {
    size_t num;
    struct mxentry *exchange[];
} DnsMxResponse;

extern DnsResolver *DnsResolver_new(void);
extern void DnsResolver_free(DnsResolver *self);

extern void DnsAResponse_free(DnsAResponse *self);
extern void DnsAaaaResponse_free(DnsAaaaResponse *self);
extern void DnsMxResponse_free(DnsMxResponse *self);
extern void DnsTxtResponse_free(DnsTxtResponse *self);
extern void DnsSpfResponse_free(DnsSpfResponse *self);
extern void DnsPtrResponse_free(DnsPtrResponse *self);

extern int DnsResolver_lookupA(DnsResolver *self, const char *domain, DnsAResponse **resp);
extern int DnsResolver_lookupAaaa(DnsResolver *self, const char *domain, DnsAaaaResponse **resp);
extern int DnsResolver_lookupMx(DnsResolver *self, const char *domain, DnsMxResponse **resp);
extern int DnsResolver_lookupTxt(DnsResolver *self, const char *domain, DnsTxtResponse **resp);
extern int DnsResolver_lookupSpf(DnsResolver *self, const char *domain, DnsSpfResponse **resp);
extern int DnsResolver_lookupPtr(DnsResolver *self, int af, const void *addr,
                                 DnsPtrResponse **resp);

extern const char *DnsResolver_getErrorString(DnsResolver *self);

#define DNS_IP4_REVENT_SUFFIX "in-addr.arpa."
#define DNS_IP6_REVENT_SUFFIX "ip6.arpa."

#define DNS_IP4_REVENT_MAXLEN sizeof("123.456.789.012." DNS_IP4_REVENT_SUFFIX)
#define DNS_IP6_REVENT_MAXLEN sizeof("0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f." DNS_IP6_REVENT_SUFFIX)

#endif /* __DNSRESOLV_H__ */
