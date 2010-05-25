/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfquery.c 415 2008-08-20 13:15:18Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfquery.c 415 2008-08-20 13:15:18Z takahiko $");

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "ptrop.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "sidfpolicy.h"
#include "sidfrequest.h"
#include "sidfenum.h"

static void
usage(void)
{
    fprintf(stderr, "sidfquery [-46mps] username@domain IP-address\n");
    exit(EX_USAGE);
}   // end functiion : usage

int
main(int argc, char **argv)
{
    int af = AF_INET;
    SidfRecordScope scope = SIDF_RECORD_SCOPE_SPF1;

    int c;
    while (-1 != (c = getopt(argc, argv, "46mpsh"))) {
        switch (c) {
        case '4':  // IPv4
            af = AF_INET;
            break;
        case '6':  // IPv6
            af = AF_INET6;
            break;
        case 'm':  // SIDF/mfrom
            scope = SIDF_RECORD_SCOPE_SPF2_MFROM;
            break;
        case 'p':  // SIDF/pra
            scope = SIDF_RECORD_SCOPE_SPF2_PRA;
            break;
        case 's':  // SPF
            scope = SIDF_RECORD_SCOPE_SPF1;
            break;
        case 'h':
            usage();
            break;
        default:
            fprintf(stderr, "illegal option: -%c\n", c);
            usage();
            break;
        }   // end switch
    }   // end while

    argc -= optind;
    argv += optind;

    if (argc < 2) {
        usage();
    }   // end if

    DnsResolver *resolver = DnsResolver_new();
    if (NULL == resolver) {
        fprintf(stderr, "resolver initialization failed: err=%s\n", strerror(errno));
        exit(EX_OSERR);
    }   // end if

    const char *mailbox = argv[0];
    const char *ipaddr = argv[1];

    SidfPolicy *policy = SidfPolicy_new();
    if (NULL == policy) {
        fprintf(stderr, "SidfPolicy_new failed: err=%s\n", strerror(errno));
        exit(EX_OSERR);
    }   // end if
    policy->lookup_spf_rr = false;

    SidfRequest *request = SidfRequest_new(policy, resolver);
    if (NULL == request) {
        fprintf(stderr, "SidfRequest_new failed: err=%s\n", strerror(errno));
        exit(EX_OSERR);
    }   // end if

    if (!SidfRequest_setIpAddrString(request, af, ipaddr)) {
        fprintf(stderr, "IP address invalid: ip-address=%s\n", ipaddr);
        usage();
    }   // end if
    const char *dummy;
    InetMailbox *envfrom = InetMailbox_build2821Mailbox(mailbox, STRTAIL(mailbox), &dummy, NULL);
    SidfRequest_setSender(request, envfrom);
    SidfRequest_setHeloDomain(request, InetMailbox_getDomain(envfrom));

    // SPF/Sender ID evaluation
    SidfScore score = SidfRequest_eval(request, scope);
    const char *spfresultexp = SidfEnum_lookupScoreByValue(score);
    fprintf(stdout, "%s %s %s\n", mailbox, ipaddr, spfresultexp);

    // clean up
    SidfRequest_free(request);
    SidfPolicy_free(policy);
    DnsResolver_free(resolver);
    InetMailbox_free(envfrom);

    exit(EX_OK);
}   // end function : main
