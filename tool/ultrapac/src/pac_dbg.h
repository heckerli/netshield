/* $Id: pac_dbg.h 3265 2006-06-09 21:16:12Z rpang $ */

#ifndef pac_dbg_h
#define pac_dbg_h

#include <assert.h>
#include <stdio.h>

extern bool FLAGS_pac_debug;

#define ASSERT(x)	assert(x)

#ifdef WIN32
#define DEBUG_MSG(x, ...)	if ( FLAGS_pac_debug ) fprintf(stderr, x, __VA_ARGS__)
#else
#define DEBUG_MSG(x...)	if ( FLAGS_pac_debug ) fprintf(stderr, x)
#endif

#endif /* pac_dbg_h */
