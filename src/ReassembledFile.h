#ifndef _REASSEMBLED_FILE_H_
#define _REASSEMBLED_FILE_H_

#include "NetShield.h"
#include "Scheduler.h"
#include "PacketDrivenSource.h"

class ReassembledFile : public PacketDrivenSource
{
public:
    ReassembledFile();
    ~ReassembledFile();
    
    virtual Scheduler * setScheduler(Scheduler * scheduler);
    virtual INT32_T run();
    
    INT8_T open(const INT8_T * fileName);
    INT8_T close();
    
protected:
    Scheduler * scheduler;
    Connection * conn;
    FILE * fp;
    
    UINT8_T * buf;
    UINT32_T bufLength;
    UINT32_T contentLength;
};

#endif
