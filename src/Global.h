#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#ifdef GLOBAL_VAR
#define GLOBAL_EXTERN
#define INIT_VAL(code)  = (code) 
#else
#define GLOBAL_EXTERN extern
#define INIT_VAL(code) 
#endif

#include <map>

using namespace std;

#include "NetShield.h"
#include "argtable/argtable2.h"
#include "tinyxml/tinyxml.h"

GLOBAL_EXTERN struct arg_file * configFile      INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_int  * intf            INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_str  * filter          INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_str  * proto           INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_file * reassembled     INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_file * trace           INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_file * writeFile       INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * listIF          INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * printcs         INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * parseOnly       INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * usePac          INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * writeLog        INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * filterError     INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_int  * repeat          INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * silent          INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * tcpReassembly   INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * udpReassembly   INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * seqMatch        INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_int  * initConn        INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_lit  * help            INIT_VAL(NULL);
GLOBAL_EXTERN struct arg_end  * end             INIT_VAL(NULL);

GLOBAL_EXTERN Protocol protocol;
GLOBAL_EXTERN TiXmlDocument config;

GLOBAL_EXTERN UINT32_T initConnNum              INIT_VAL(1);

GLOBAL_EXTERN UINT32_T maxSiSize INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxAiSize INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxBiSize INIT_VAL(0);

GLOBAL_EXTERN UINT32_T currentIntRangeStructNum             INIT_VAL(0);
GLOBAL_EXTERN UINT32_T currentIntRangeStructKeyTotalSize    INIT_VAL(0);
GLOBAL_EXTERN UINT32_T currentIntRangeStructDataTotalSize   INIT_VAL(0);

GLOBAL_EXTERN UINT32_T maxIntRangeStructNum                 INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxIntRangeStructKeyTotalSize        INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxIntRangeStructDataTotalSize       INIT_VAL(0);

GLOBAL_EXTERN UINT32_T currentIntRangeMatcherTotalSize      INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxIntRangeMatcherTotalSize          INIT_VAL(0);

GLOBAL_EXTERN UINT32_T currentDFAStructTotalSize            INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxDFAStructTotalSize                INIT_VAL(0);

GLOBAL_EXTERN UINT32_T currentDFAMatcherTotalSize           INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxDFAMatcherTotalSize               INIT_VAL(0);

GLOBAL_EXTERN UINT32_T currentTrieStructTotalSize           INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxTrieStructTotalSize               INIT_VAL(0);

GLOBAL_EXTERN UINT32_T currentTrieMatcherTotalSize          INIT_VAL(0);
GLOBAL_EXTERN UINT32_T maxTrieMatcherTotalSize              INIT_VAL(0);

GLOBAL_EXTERN UINT32_T maxLiveConnectionNum                 INIT_VAL(0);

GLOBAL_EXTERN UINT32_T accMatchedFlowNum                    INIT_VAL(0);

GLOBAL_EXTERN map<Tuple5, bool> filterTuple5Map;

GLOBAL_EXTERN map<UINT16_T, UINT32_T> ruleMap;

GLOBAL_EXTERN UINT32_T validPduNum                          INIT_VAL(0);

extern Protocol PROTOCOL_HTTP;
extern Protocol PROTOCOL_DCE_RPC;
extern Protocol PROTOCOL_DNS;

#endif
