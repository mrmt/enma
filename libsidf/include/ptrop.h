/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: ptrop.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __PTROP_H__
#define __PTROP_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#ifndef PTRINIT
/// NULL でないポインタを free() して NULL をセットするマクロ
#define PTRINIT(__p) \
	do { \
		if (__p) { \
			free(__p); \
			(__p) = NULL; \
		} \
	} while (0)
#endif

#ifndef SETDEREF
/// ポインタが NULL でないことを確認してから，ポインタが指す領域に値を代入するマクロ
#define SETDEREF(__p, __v) \
	do { \
		if (__p) { \
			*(__p) = (__v); \
		} \
	} while (0)
#endif

#ifndef NNSTR
/// *printf での SEGV 除けマクロ
#define NNSTR(__s)	((__s) ? (__s) : "(NULL)")
#endif

#ifndef PTROR
/// 第一引数が NULL の場合に第二引数を返すマクロ
#define PTROR(__p, __q)	((__p) ? (__p) : (__q))
#endif

#ifndef STRTAIL
#define STRTAIL(__s)	((__s) + strlen(__s))
#endif

/// 構造体のメンバのポインタへ offset を指定してアクセスするマクロ
#ifndef STRUCT_MEMBER_P
#define STRUCT_MEMBER_P(struct_p, struct_offset) \
        ((void *) ((char *) (struct_p) + (ptrdiff_t) (struct_offset)))
#endif
/// 構造体のメンバの値へ offset と型を指定してアクセスするマクロ
#ifndef STRUCT_MEMBER
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
        (*(member_type *) STRUCT_MEMBER_P((struct_p), (struct_offset)))
#endif

#endif /* __PTROP_H__ */
