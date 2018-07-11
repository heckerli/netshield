#ifndef _NETSHIELD_TYPE_H_
#define _NETSHIELD_TYPE_H_

#ifdef WIN32
#pragma warning(disable:4996)
#endif

#if defined(WIN32) || defined(WIN64)
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <cstring>
#include <string>
#include <iostream>

#include "snprintf/snprintf.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#if defined(WIN64)
    
typedef void            VOID_T;
typedef bool            BOOL_T;
typedef char            INT8_T;
typedef unsigned char   UINT8_T;
typedef short           INT16_T;
typedef unsigned short  UINT16_T;
typedef int             INT32_T;
typedef unsigned int    UINT32_T;

typedef char            int8;
typedef short           int16;
typedef long            int32;
typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned long   uint32;

#else

typedef void            VOID_T;
typedef bool            BOOL_T;
typedef char            INT8_T;
typedef unsigned char   UINT8_T;
typedef short           INT16_T;
typedef unsigned short  UINT16_T;
typedef int             INT32_T;
typedef unsigned int    UINT32_T;

typedef char            int8;
typedef short           int16;
typedef long            int32;
typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned long   uint32;

#endif

typedef std::string     STRING_T;

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE true
#endif

#ifndef FALSE
#define FALSE false
#endif

enum TransLayerProtocol
{
    TLP_NULL = 0,
    TLP_TCP,
    TLP_UDP,
};

enum AppLayerProtocol
{
    ALP_NULL = 0,
    ALP_HTTP,
    ALP_DCE_RPC,
    ALP_DNS,
};

class Protocol
{
public:
    TransLayerProtocol tlp;
    AppLayerProtocol alp;
    
    Protocol()
    {
        this->tlp = TLP_NULL;
        this->alp = ALP_NULL;
    }
    
    Protocol(TransLayerProtocol tlp, AppLayerProtocol alp)
    {
        this->tlp = tlp;
        this->alp = alp;
    }
    
    Protocol(const Protocol & protocol)
    {
        this->tlp = protocol.tlp;
        this->alp = protocol.alp;
    }
    
    ~Protocol()
    {
    }
    
    Protocol & operator=(const Protocol & protocol)
    {
        this->tlp = protocol.tlp;
        this->alp = protocol.alp;
        
        return *this;
    }
    
    bool operator==(const Protocol & protocol)
    {
        return this->tlp == protocol.tlp && this->alp == protocol.alp;
    }
};

enum TCPState
{
    NS_TCP_IDLE = 0x00000000,
    NS_TCP_ESTABLISHED = 0x00000001,
    NS_TCP_DATA = 0x00000002,
    NS_TCP_CLOSE = 0x00000004,
    NS_TCP_RESET = 0x00000008,
    NS_TCP_TIMEOUT = 0x00000010,
};

enum FlowDir
{
    ORIG_TO_RESP = 0,
    RESP_TO_ORIG,
};

class Tuple5
{
public:
    UINT32_T origIP;
    UINT16_T origPort;
    UINT32_T respIP;
    UINT16_T respPort;
    UINT16_T protocol;
    
    Tuple5()
    {
    }
    
    Tuple5(const Tuple5 & tuple5)
    {
        this->origIP   = tuple5.origIP;
        this->origPort = tuple5.origPort;
        this->respIP   = tuple5.respIP;
        this->respPort = tuple5.respPort;
        this->protocol = tuple5.protocol;
    }
    
    ~Tuple5()
    {
    }
    
    Tuple5 & operator=(const Tuple5 & tuple5)
    {
        this->origIP   = tuple5.origIP;
        this->origPort = tuple5.origPort;
        this->respIP   = tuple5.respIP;
        this->respPort = tuple5.respPort;
        this->protocol = tuple5.protocol;

		return *this;
    }
    
    bool operator == (const Tuple5 & tuple)const
    {
        if(this->origIP != tuple.origIP)
        {
            return false;
        }
        else if(this->origPort != tuple.origPort)
        {
            return false;
        }
        else if(this->respIP != tuple.respIP)
        {
            return false;
        }
        else if(this->respPort != tuple.respPort)
        {
            return false;
        }
        else if(this->protocol != tuple.protocol)
        {
            return false;
        }
        
        return true;
    }
    
    bool operator < (const Tuple5 & tuple)const
    {
        if(this->origIP != tuple.origIP)
        {
            return this->origIP < tuple.origIP;
        }
        else if(this->origPort != tuple.origPort)
        {
            return this->origPort < tuple.origPort;
        }
        else if(this->respIP != tuple.respIP)
        {
            return this->respIP < tuple.respIP;
        }
        else if(this->respPort != tuple.respPort)
        {
            return this->respPort < tuple.respPort;
        }
        else if(this->protocol != tuple.protocol)
        {
            return this->protocol < tuple.protocol;
        }
        
        return false;
    }
    
    STRING_T toString()const
    {
        INT8_T str[64];
        INT32_T length = snprintf(str, 32, "%s:%u", int_ntoa(origIP), origPort);
        snprintf(str + length, 31, " - %s:%u", int_ntoa(respIP), respPort);

		return STRING_T(str);
    }
    
    static void sort(Tuple5 * tuple5)
    {
        if(tuple5->origIP < tuple5->respIP)
        {
            return;
        }
        else if(tuple5->origIP > tuple5->respIP)
        {
            UINT32_T tempIP = tuple5->origIP;
            tuple5->origIP = tuple5->respIP;
            tuple5->respIP = tempIP;
            
            UINT16_T tempPort = tuple5->origPort;
            tuple5->origPort = tuple5->respPort;
            tuple5->respPort = tempPort;
        }
        else if(tuple5->origPort > tuple5->respPort)
        {
            UINT16_T tempPort = tuple5->origPort;
            tuple5->origPort = tuple5->respPort;
            tuple5->respPort = tempPort;
        }
    }
};

class TCPFlowInfo
{
public:
    UINT32_T state;
    Tuple5 tuple5;
    FlowDir dir;
};

enum LineBreakStyle
{ 
    CR_AND_LF,
    CRLF_OR_LF,
};

enum FieldParsingState
{
    INVALID,
    INPROCESS,
    FINISHED,
};

enum FieldMatchingState
{
    NEVER_MATCHED = 0x00000000,
    STRING_MATCHED = 0x00000001,
    REGEX_MATCHED = 0x00000002,
    LENGTH_MATCHED = 0x00000004,
};

class Field
{
public:
    bool isPermanent;
    FieldParsingState parsingState;
    UINT32_T matchingState;
    UINT8_T * dataBegin;
    UINT8_T * dataEnd;      // 注意，这个end是虚的，它所指向的是最后一个有效数据的下一个
    
    Field()
    {
        reset();
    }
    
    Field(const Field & field)
    : isPermanent(field.isPermanent), parsingState(field.parsingState),
      matchingState(field.matchingState),
      dataBegin(field.dataBegin), dataEnd(field.dataEnd)
    {
    }
    
    ~Field()
    {
    }
    
    Field & operator=(const Field & field)
    {
        if(isPermanent == true)
        {
            delete dataBegin;
        }
        
        this->isPermanent = field.isPermanent;
        this->parsingState = field.parsingState;
        this->matchingState = field.matchingState;
        this->dataBegin = field.dataBegin;
        this->dataEnd = field.dataEnd;
        
        return *this;
    }
    
    INT32_T reset()
    {
        isPermanent = false;
        parsingState = INVALID;
        matchingState = NEVER_MATCHED;
        dataBegin = NULL;
        dataEnd = NULL;

		return 0;
    }
    
    INT32_T releaseMemory()
    {
        if(isPermanent == true)
        {
            delete dataBegin;
        }
        
        reset();

		return 0;
    }
    
    INT32_T makePermanent()
    {
        if(isPermanent == true || dataBegin == NULL)
        {
            return 0;
        }
        
        UINT8_T * temp = dataBegin;
        UINT32_T dataLength = dataEnd - dataBegin;
        dataBegin = new UINT8_T[dataLength];
        if(dataBegin == NULL)
        {
            fprintf(stderr, "Runtime error: %s:%d\n", __FILE__, __LINE__);
            exit(0);
        }
        
        memcpy(dataBegin, temp, dataLength);
        dataEnd = dataBegin + dataLength;
        
        isPermanent = true;
                
        return 0;
    }
};

class Rule
{
public:
    UINT16_T columnID;
    UINT16_T ruleID;
    
    Rule()
    {
    }
    
    Rule(UINT16_T columnID, UINT16_T ruleID)
    {
        this->columnID = columnID;
        this->ruleID = ruleID;
    }
};

std::ostream & operator<<(std::ostream & out, const Rule & rule);

#endif
