/*
 * Copyright (c) 2008 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: keywordmap.h 41 2008-05-28 04:57:16Z takahiko $
 */

#ifndef __KEYWORDMAP_H__
#define __KEYWORDMAP_H__

typedef struct KeywordMap {
    const char *keyword;
    const int value;
} KeywordMap;

extern int KeywordMap_lookupByString(const KeywordMap *table, const char *keyword);
extern int KeywordMap_lookupByStringSlice(const KeywordMap *table, const char *head,
                                          const char *tail);
extern int KeywordMap_lookupByCaseString(const KeywordMap *table, const char *keyword);
extern int KeywordMap_lookupByCaseStringSlice(const KeywordMap *table, const char *head,
                                              const char *tail);

extern const char *KeywordMap_lookupByValue(const KeywordMap *table, int value);

#endif /* __KEYWORDMAP_H__ */
