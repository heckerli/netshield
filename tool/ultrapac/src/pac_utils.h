// $Id: pac_utils.h 3225 2006-06-08 00:00:01Z vern $

#ifndef pac_utils_h
#define pac_utils_h

#include <sys/types.h>
#include <string>
using namespace std;

char* copy_string(const char* s);
string strfmt(const char* fmt, ...);
char* nfmt(const char* fmt, ...);

// const char* fmt(const char* fmt, ...);
#ifdef WIN32
#define fmt(x, ...) strfmt(x, __VA_ARGS__).c_str()
#else
#define fmt(x...) strfmt(x).c_str()
#endif

#endif /* pac_utils_h */
