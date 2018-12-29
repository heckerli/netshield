#include "NetShield.h"
#include "Libnids.h"
#include "Param.h"

#ifdef __cplusplus

extern "C" {
	
#endif
	
#ifdef WIN32
#include "win32/pcap.h"
#include "win32/nids.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libpcap.lib")
#pragma comment(lib, "libnids.lib")
#else
#include <pcap.h>
#include <nids.h>
#endif
	
#ifdef __cplusplus
	
}

#endif

Scheduler * Libnids::scheduler = NULL;
ObjectPool<Connection> * Libnids::connPool = NULL;
set<Connection *> Libnids::liveConnSet;

Libnids::Libnids(TransLayerProtocol tlp)
{
    // DEBUG_WRAP(DebugMessage("Libnids::Libnids()\n"););
    
    this->tlp = tlp;
    
    if(tlp == TLP_TCP)
    {
        if(Libnids::connPool == NULL)
        {
            printf("Connection pool init size = %u\n", initConnNum);
            Libnids::connPool = new ObjectPool<Connection>(initConnNum);
            verify(Libnids::connPool);
        }
    }
    else if(tlp == TLP_UDP)
    {
    }
    else
    {
        fprintf(stderr, "Transport layer protocol not specified!\n");
        exit(0);
    }
}

Libnids::~Libnids()
{
    // DEBUG_WRAP(DebugMessage("Libnids::~Libnids()\n"););
    
    if(Libnids::connPool != NULL)
    {
        delete Libnids::connPool;
        Libnids::connPool = NULL;
    }
    
    set<Connection *>::iterator it = liveConnSet.begin();
    while(it != liveConnSet.end())
    {
        Connection * conn = *it;
        conn->finish();
        
        delete conn;
        
        it++;
    }
    liveConnSet.clear();
}

INT32_T Libnids::init()
{
    if (!nids_init())
    {
        fprintf(stderr, "%s\n", nids_errbuf);
        exit(1);
    }

    if(tlp == TLP_TCP)
    {
        nids_register_tcp((void *)Libnids::packetDrivenTCPCallback);
    }
    else if(tlp == TLP_UDP)
    {
        nids_register_udp((void *)udpCallback);
    }

	return 0;
}

Scheduler * Libnids::setScheduler(Scheduler * scheduler)
{
    Scheduler * oldScheduler = Libnids::scheduler;
    Libnids::scheduler = scheduler;
        
    return oldScheduler;
}

INT32_T Libnids::run()
{
    nids_run();

	return 0;
}

void Libnids::packetDrivenTCPCallback(void * tcpFlow, void ** param)
{
    TCPFlowInfo tcpFlowInfo;
    UINT8_T * data = NULL;
    UINT32_T dataLength = 0;
    
    tcpFlowInfo.state = NS_TCP_IDLE;
        
    struct tcp_stream * tcp_flow = (struct tcp_stream *)tcpFlow;
    
    tcpFlowInfo.tuple5.origIP = tcp_flow->addr.saddr;
    tcpFlowInfo.tuple5.origPort = tcp_flow->addr.source;
    tcpFlowInfo.tuple5.respIP = tcp_flow->addr.daddr;
    tcpFlowInfo.tuple5.respPort = tcp_flow->addr.dest;
    tcpFlowInfo.tuple5.protocol = 6;    // TCP
    
    Connection * conn = NULL;
        
    if (tcp_flow->nids_state == NIDS_JUST_EST)
    {
		// connection described by tcp_flow is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (tcp_flow->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		tcp_flow->client.collect++; // we want data received by a client
		tcp_flow->server.collect++; // and by a server, too
		
		tcpFlowInfo.state = NS_TCP_ESTABLISHED;
		data = NULL;
        dataLength = 0;
        
        conn = Libnids::connPool->getObject();
        *param = conn;
        
        if(liveConnSet.find(conn) == liveConnSet.end())
        {
            liveConnSet.insert(conn);
            if(liveConnSet.size() > maxLiveConnectionNum)
            {
                maxLiveConnectionNum = liveConnSet.size();
            }
        }
    }
	else if (tcp_flow->nids_state == NIDS_RESET)
    {
        tcpFlowInfo.state = NS_TCP_RESET;
        data = NULL;
        dataLength = 0;
        
        conn = (Connection *)(*param);
        conn->finish();
        if(liveConnSet.find(conn) != liveConnSet.end())
        {
            liveConnSet.erase(conn);
        }
        
        Libnids::connPool->releaseObject(conn);
    }
    else if(tcp_flow->nids_state == NIDS_CLOSE)
    {
        tcpFlowInfo.state = NS_TCP_CLOSE;
        data = NULL;
        dataLength = 0;
        
        conn = (Connection *)(*param);
        conn->finish();
        if(liveConnSet.find(conn) != liveConnSet.end())
        {
            liveConnSet.erase(conn);
        }
        
        Libnids::connPool->releaseObject(conn);
    }
	else if (tcp_flow->nids_state == NIDS_DATA)
    {
		struct half_stream * hlf = NULL;

		if (tcp_flow->server.count_new > 0)
        {
            hlf = &tcp_flow->server;
            tcpFlowInfo.dir = ORIG_TO_RESP;
        }
        
        if (tcp_flow->client.count_new > 0)
        {
            hlf = &tcp_flow->client;
            tcpFlowInfo.dir = RESP_TO_ORIG;
        }
        
        tcpFlowInfo.state = NS_TCP_DATA;
        data = (UINT8_T *)(hlf->data);
        dataLength = hlf->count_new;
        
        conn = (Connection *)(*param);
    }
    
    if(Libnids::scheduler != NULL)
    {
		Libnids::scheduler->newFlowData(&tcpFlowInfo, conn, data, dataLength);
    }
}

void Libnids::udpCallback(struct tuple4 * addr, char * buf, int len, struct ip * iph)
{
	Tuple5 tuple5;
    tuple5.origIP = addr->saddr;
    tuple5.origPort = addr->source;
    tuple5.respIP = addr->daddr;
    tuple5.respPort = addr->dest;
    tuple5.protocol = 17;    // UDP
    
    if(Libnids::scheduler != NULL)
    {
        Libnids::scheduler->newPacketData(&tuple5, (UINT8_T *)buf, len);
    }
}

INT32_T Libnids::setFileToRead(const INT8_T * fileName)
{
    nids_params.filename = (char *)fileName;

	return 0;
}

INT32_T Libnids::setInterface(UINT32_T ifNum)
{
    if (ifNum < 0)
    {
        fprintf(stderr, "Invalid adapter index\n");
        exit(0);
    }
    
    pcap_if_t * devpointer = NULL;
    INT8_T ebuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devpointer, ebuf) < 0)
    {
        fprintf(stderr, "%s", ebuf);
    }
    else
    {
        for (UINT32_T i = 0; i < ifNum - 1; i++)
        {
            devpointer = devpointer->next;
            if (devpointer == NULL)
            {
                fprintf(stderr, "Invalid adapter index\n");
            }
        }
    }
    
    nids_params.device = devpointer->name;

	return 0;
}

INT32_T Libnids::setFilter(const INT8_T * filter)
{
    nids_params.pcap_filter = (char *)filter;

	return 0;
}
