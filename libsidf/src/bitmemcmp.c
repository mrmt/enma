/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: bitmemcmp.c 368 2008-08-15 14:23:21Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: bitmemcmp.c 368 2008-08-15 14:23:21Z takahiko $");

#include <inttypes.h>
#include <string.h>
#include "bitmemcmp.h"

/**
 * 2つのメモリ領域の中身を指定したビット数分比較する.
 * @return s1 と s2 の中身が等しければ 0, 等しくない場合は memcmp() と同じ.
 */
int
bitmemcmp(const void *s1, const void *s2, size_t bits)
{
    /*
     * libbind の bitncmp の代替関数.
     * libbind の bitncmp は第3引数に8の倍数を指定した場合に,
     * 指定したビット数を超える領域にアクセスし, アクセス違反をおこす.
     * ISC に報告済み (2369, RT #18054)
     * BIND 9.3.6, 9.4.3, 9.6.0 に修正が取り込まれるはずなので,
     * それ以降の libbind の bitncmp() で置き換えてよい.
     */

    static const uint8_t bitmask[] = {
        0,
        0x80, 0xc0, 0xe0, 0xf0,
        0xf8, 0xfc, 0xfe, 0xff,
    };

    size_t bytes = bits / 8;
    int cmpstat = memcmp(s1, s2, bytes);
    if (0 != cmpstat) {
        return cmpstat;
    }   // end if

    size_t oddbits = bits % 8;
    if (oddbits != 0) {
        uint8_t odd1 = ((const uint8_t *) s1)[bytes];
        uint8_t odd2 = ((const uint8_t *) s2)[bytes];
        if ((odd1 & bitmask[oddbits]) != (odd2 & bitmask[oddbits])) {
            return (odd1 & bitmask[oddbits]) > (odd2 & bitmask[oddbits]) ? 1 : -1;
        }   // end if
    }   // end if

    return 0;
}   // end function : bitmemcmp
