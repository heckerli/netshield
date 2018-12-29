#ifndef _UDP_REASSEMBLER_H_
#define _UDP_REASSEMBLER_H_

#include "NetShield.h"
#include "PacketAnalyzer.h"

class UDPReassembler : public PacketAnalyzer
{
public:
    UDPReassembler();
    
    ~UDPReassembler();
    
    virtual INT32_T run();
    
    static INT32_T setOutputFile(const char * fileName);
    
    static UINT32_T appBytes;
    static UINT32_T packetNum;

protected:
    static FILE * outputFile;
    static UINT32_T instanceNum;
};

#endif
