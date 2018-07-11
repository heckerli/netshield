#ifndef _PACKET_DRIVEN_SOURCE_H_
#define _PACKET_DRIVEN_SOURCE_H_

#include "NetShield.h"
#include "Scheduler.h"

class PacketDrivenSource : public Runnable
{
public:
    PacketDrivenSource();
    ~PacketDrivenSource();
    
    virtual Scheduler * setScheduler(Scheduler * scheduler) = 0;
    virtual INT32_T run() = 0;
};

#endif
