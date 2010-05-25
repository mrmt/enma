/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfpolicy.h 86 2008-06-20 08:30:57Z takahiko $
 */

#ifndef __SIDFPOLICY_H__
#define __SIDFPOLICY_H__

#include <stdbool.h>
#include "sidf.h"

typedef struct SidfPolicy {
    // SPF RR (type 99) を引くか
    bool lookup_spf_rr;
    // explanation レコードを引くか
    bool lookup_exp;
    // SPF/SID の検証をしているホスト/ドメイン名, "r" マクロの展開に使用される
    char *checking_domain;
    // マクロ展開の際, 展開過程を中断する長さの閾値
    unsigned int macro_expansion_limit;
    // SPFレコード中のどのメカニズムにもマッチしなかった場合, Neutral を返す前にこのレコードの評価を挟む
    // 評価されるタイミングは redirect modifier が存在しなかった場合
    char *local_policy;
    // local_policy によって "Fail" になった場合に使用する explanation を設定する. マクロ使用可.
    char *local_policy_explanation;
    // 1回のSPF評価で許容するDNSルックアップを伴うメカニズムの最大数, RFC4408 では 10 と定めている
    unsigned int max_dns_mech;
    // check_host() 関数の <domain> 引数が許容する文字列の最大長, RFC4408 では 63 と定めている
    unsigned int max_domain_len;
    // mx メカニズム評価中に1回のMXレコードのルックアップに対するレスポンスとして受け取るRRの最大数, RFC4408 では 10 と定めている
    unsigned int max_mxrr_per_mxmech;
    // ptr メカニズム評価中に1回のPTRレコードのルックアップに対するレスポンスとして受け取るRRの最大数, RFC4408 では 10 と定めている
    unsigned int max_ptrrr_per_ptrmech;
    // "all" メカニズムにどんな qualifier が付いていようとスコアを上書きする.
    // SIDF_SCORE_NULL の場合は通常動作 (レコードに書かれている qualifier を使用)
    SidfScore overwrite_all_directive_score;
    // "+all" を評価したらログに記録する.
    bool logging_plus_all_directive;
} SidfPolicy;

extern SidfPolicy *SidfPolicy_new(void);
extern void SidfPolicy_free(SidfPolicy *self);
extern SidfStat SidfPolicy_setCheckingDomain(SidfPolicy *self, const char *domain);
extern SidfStat SidfPolicy_setLocalPolicyDirectives(SidfPolicy *self, const char *policy);
extern SidfStat SidfPolicy_setLocalPolicyExplanation(SidfPolicy *self, const char *explanation);

#endif /* __SIDFPOLICY_H__ */
