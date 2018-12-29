#ifndef _UTIL_H_
#define _UTIL_H_

#include <cstdio>
#include <string>

using namespace std;

#include "NetShield.h"
#include "TrieStruct.h"
#include "DFAStruct.h"
#include "IntRangeStruct.h"
#include "tinyxml/tinyxml.h"

#ifdef DEBUG
#define DEBUG_WRAP(code) code
void DebugMessage(const char * format, ...);
#else
#define DEBUG_WRAP(code)
#endif

#ifndef verify
#define verify(code) if(!(code)) { fprintf(stderr, "Runtime error: %s:%d\n", __FILE__, __LINE__); exit(0); }
#endif

#define TIMERSUB(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

/* INT32_T strncmpi(const INT8_T *s1, const INT8_T *s2, UINT32_T n); */

class Connection;

INT8_T ReportError(Connection * conn, const INT8_T * format, /*args*/ ...);

#define LSB16(x) ((x) & 0xffff)
#define MSB16(x) (((x) >> 16) & 0xffff)
#define MAKE_UINT32(msb16, lsb16) (((msb16) << 16) | (lsb16))

INT32_T loadStringStruct(TrieStruct<Rule> * trie, TiXmlHandle & hString);
INT32_T loadDFAStruct(DFAStruct<Rule> * dfa, TiXmlHandle & hRegex);
INT32_T loadLengthStruct(IntRangeStruct<Rule> * intRangeStruct, TiXmlHandle & hLength);

INT32_T printField(const Field & field, FILE * fp);

bool hasDollar(const string & regex);
void removeDollar(string & regex);

inline UINT32_T int_aton(const UINT8_T * dataBegin, UINT32_T dataLength)
{
    UINT32_T result = 0;
    UINT8_T * pr = (UINT8_T *)(&result);
    
    const UINT8_T * p = dataBegin;
    
    while(*p >= '0' && *p <= '9')
    {
        pr[0] = pr[0] * 10 + *p - '0';
        p++;
    }
    
    p++;
    
    while(*p >= '0' && *p <= '9')
    {
        pr[1] = pr[1] * 10 + *p - '0';
        p++;
    }
    
    p++;
    
    while(*p >= '0' && *p <= '9')
    {
        pr[2] = pr[2] * 10 + *p - '0';
        p++;
    }
    
    p++;
    
    while(p < dataBegin + dataLength && *p >= '0' && *p <= '9')
    {
        pr[3] = pr[3] * 10 + *p - '0';
        p++;
    }
    
    return result;
}

#if defined(WIN32) || defined(WIN64)
int ns_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

#define NEW_MATCHER(_type_, _matcher_, _struct_) if((_struct_) != NULL) \
    { \
        (_matcher_) = new _type_(_struct_); \
        verify(_matcher_); \
    } \
    else \
    { \
        (_matcher_) = NULL; \
    }

#define RESET_MATCHER(_matcher_) if(_matcher_) { (_matcher_)->reset(); }

#endif
