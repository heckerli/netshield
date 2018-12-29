#ifndef _TCP_REASSEMBLER_H_
#define _TCP_REASSEMBLER_H_

#include "NetShield.h"
#include "FlowAnalyzer.h"
#include "BlockList.h"
#include "MemPool.h"

class TCPReassembler : public FlowAnalyzer
{
public:
    TCPReassembler(FlowHandler * flow, FlowDir dir);
    
    virtual ~TCPReassembler();
    
    virtual INT32_T reset(FlowHandler * flow, FlowDir dir);
    
    virtual INT32_T run();
    virtual INT32_T finish();
    
    static INT32_T setOutputFile(const char * fileName);
    
    static UINT32_T appBytes;
    static UINT32_T flowNum;

protected:
    static FILE * outputFile;
    static UINT32_T instanceNum;
    static MemPool * memPool;

    static void addToList(UINT8_T * data, UINT32_T dataLength, BlockList * l);
    static void writeToFile(FILE * fp, FlowDir dir, BlockList * l);
    
    BlockList blockList;
};

#endif
