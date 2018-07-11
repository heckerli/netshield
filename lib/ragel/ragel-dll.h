// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the RAGELDLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// RAGELDLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.

#ifndef _RAGEL_DLL_H_
#define _RAGEL_DLL_H_

#ifdef RAGELDLL_EXPORTS
#define RAGELDLL_API __declspec(dllexport)
#else
#define RAGELDLL_API __declspec(dllimport)
#endif

#include "ragel-lib.h"

#endif
