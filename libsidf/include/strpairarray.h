/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: strpairarray.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __STRPAIRARRAY_H__
#define __STRPAIRARRAY_H__

#include <sys/types.h>

#include "ptrarray.h"

typedef PtrArray StrPairArray;

extern StrPairArray *StrPairArray_new(size_t size);
extern void StrPairArray_get(const StrPairArray *self, size_t pos, const char **pkey,
                             const char **pval);
extern const char *StrPairArray_getKey(const StrPairArray *self, size_t pos);
extern const char *StrPairArray_getValue(const StrPairArray *self, size_t pos);
extern int StrPairArray_set(StrPairArray *self, size_t pos, const char *key, const char *val);
extern int StrPairArray_setWithLength(StrPairArray *self, size_t pos, const char *key,
                                      size_t keylen, const char *val, size_t vallen);
extern int StrPairArray_append(StrPairArray *self, const char *key, const char *val);
extern int StrPairArray_appendWithLength(StrPairArray *self, const char *key, size_t keylen,
                                         const char *val, size_t vallenl);
extern void StrPairArray_sortByKey(StrPairArray *self);
extern void StrPairArray_sortByKeyIgnoreCase(StrPairArray *self);
extern const char *StrPairArray_binarySearchByKey(StrPairArray *self, const char *key);
extern const char *StrPairArray_binarySearchByKeyIgnoreCase(StrPairArray *self, const char *key);
extern const char *StrPairArray_linearSearchByKey(StrPairArray *self, const char *key);
extern const char *StrPairArray_linearSearchByKeyIgnoreCase(StrPairArray *self, const char *key);

#define StrPairArray_free(a)	PtrArray_free(a)
#define StrPairArray_reset(a)	PtrArray_reset(a)
#define StrPairArray_unappend(a)	PtrArray_unappend(a)
#define StrPairArray_getCount(a)	PtrArray_getCount(a)
#define StrPairArray_adjustSize(a)	PtrArray_adjustSize(a)
#define StrPairArray_reserve(a, b)	PtrArray_reserve(a, b)
#define StrPairArray_setGrowth(a, b)	PtrArray_setGrowth(a, b)
#define StrPairArray_shuffle(a)	PtrArray_shuffle(a)
#define StrPairArray_copyShallowly(a)	PtrArray_copyShallowly(a)

#endif /* __STRPAIRARRAY_H__ */
