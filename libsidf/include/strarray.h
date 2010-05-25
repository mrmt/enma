/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: strarray.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __STRARRAY_H__
#define __STRARRAY_H__

#include <sys/types.h>

#include "ptrarray.h"

typedef PtrArray StrArray;

extern StrArray *StrArray_new(size_t size);
extern const char *StrArray_get(const StrArray *self, size_t pos);
extern int StrArray_set(StrArray *self, size_t pos, const char *val);
extern int StrArray_setWithLength(StrArray *self, size_t pos, const char *val, size_t len);
extern int StrArray_append(StrArray *self, const char *val);
extern int StrArray_appendWithLength(StrArray *self, const char *val, size_t len);
extern void StrArray_sort(StrArray *self);
extern void StrArray_sortIgnoreCase(StrArray *self);
extern int StrArray_binarySearch(StrArray *self, const char *key);
extern int StrArray_binarySearchIgnoreCase(StrArray *self, const char *key);
extern int StrArray_linearSearch(StrArray *self, const char *key);
extern int StrArray_linearSearchIgnoreCase(StrArray *self, const char *key);
extern StrArray *StrArray_split(const char *record, char sep);

#define StrArray_free(a)	PtrArray_free(a)
#define StrArray_reset(a)	PtrArray_reset(a)
#define StrArray_unappend(a)	PtrArray_unappend(a)
#define StrArray_getCount(a)	PtrArray_getCount(a)
#define StrArray_adjustSize(a)	PtrArray_adjustSize(a)
#define StrArray_reserve(a, b)	PtrArray_reserve(a, b)
#define StrArray_setGrowth(a, b)	PtrArray_setGrowth(a, b)
#define StrArray_shuffle(a)	PtrArray_shuffle(a)
#define StrArray_copyShallowly(a)	PtrArray_copyShallowly(a)

#endif /* __STRARRAY_H__ */
