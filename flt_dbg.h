#ifndef _FILTDEBUG__H
#define _FILTDEBUG__H

// Verbosity
#define DL_EXTRA_LOUD  20
#define DL_VERY_LOUD   10
#define DL_LOUD        8
#define DL_INFO        6
#define DL_TRACE       5
#define DL_WARN        4
#define DL_ERROR       2
#define DL_FATAL       0

#if DBG
extern INT filterDebugLevel;
#define DEBUGP(lev, ...) do { if ((lev) <= filterDebugLevel) { DbgPrint("NDISLWF: "); DbgPrint(__VA_ARGS__); } } while(0)
#else
#define DEBUGP(lev, ...)
#endif

#endif
