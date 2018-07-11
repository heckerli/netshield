#ifndef _SCHEDULER_H_
#define _SCHEDULER_H_

#include <map>

#include "NetShield.h"
#include "Thread.h"
#include "Connection.h"
#include "ObjectPool.h"
#include "PacketHandler.h"

using namespace std;

class Scheduler
{
public:
    Scheduler(Thread * thread);
    ~Scheduler();
    INT32_T newFlowData(TCPFlowInfo * tcpFlowInfo, Connection * conn, UINT8_T * data, UINT32_T dataLength);
    INT32_T newPacketData(Tuple5 * tuple5, UINT8_T * data, UINT32_T dataLength);
    
    UINT32_T accConnectionNum;

protected:
    Thread * thread;
    PacketHandler * packetHandler;    
};

#endif
