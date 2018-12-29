#ifndef _LIBNIDS_H_
#define _LIBNIDS_H_

#include "NetShield.h"
#include "Connection.h"
#include "PacketDrivenSource.h"
#include "ObjectPool.h"

#include <set>

using namespace std;

class Libnids : public PacketDrivenSource
{
public:
    Libnids(TransLayerProtocol tlp);
    ~Libnids();
    virtual Scheduler * setScheduler(Scheduler * scheduler);
    virtual INT32_T run();
    
    INT32_T init();
    INT32_T setFileToRead(const INT8_T * fileName);
    INT32_T setInterface(UINT32_T ifNum);       // 需要在Init()之前调用
    INT32_T setFilter(const INT8_T * filter);   // 需要在Init()之前调用
    
protected:
    static void packetDrivenTCPCallback(void * tcp_flow, void ** param);
    static void udpCallback(struct tuple4 * addr, char * buf, int len, struct ip * iph);
    static Scheduler * scheduler;
    static ObjectPool<Connection> * connPool;
    static set<Connection *> liveConnSet;
    
    TransLayerProtocol tlp;
};

#endif
