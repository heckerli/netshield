#include "NetShield.h"
#include "Scheduler.h"
#include "Util.h"
#include "Global.h"

Scheduler::Scheduler(Thread * thread)
{
    // DEBUG_WRAP(DebugMessage("Scheduler::Scheduler()\n"););
    
    this->thread = thread;
    
    this->packetHandler = NULL;
    
    accConnectionNum = 0;
}

Scheduler::~Scheduler()
{
    // DEBUG_WRAP(DebugMessage("Scheduler::~Scheduler()\n"););
    if(packetHandler != NULL)
    {
        delete packetHandler;
        packetHandler = NULL;
    }
}

INT32_T Scheduler::newPacketData(Tuple5 * tuple5, UINT8_T * data, UINT32_T dataLength)
{
    if(packetHandler == NULL)
    {
        packetHandler = new PacketHandler();
        verify(packetHandler);
        packetHandler->getThread()->setParent(this->thread);
    }
    
    packetHandler->reset();
    packetHandler->newData(data, dataLength);
    
    return 0;
}

INT32_T Scheduler::newFlowData(TCPFlowInfo * tcpFlowInfo, Connection * conn, UINT8_T * data, UINT32_T dataLength)
{
    if((tcpFlowInfo->state & NS_TCP_ESTABLISHED) != 0)
    {
        // DEBUG_WRAP(DebugMessage("Connection established:\t%s\n", tcpFlowInfo->tuple5.toString().c_str()););
		// fprintf(stdout, "Connection established:\t%s\n", tcpFlowInfo->tuple5.toString().c_str());

        conn->reset(tcpFlowInfo->tuple5, thread);        
        
        accConnectionNum++;
        
        if(filterError->count > 0 && reassembled->count == 0)
        {
            Tuple5 tuple5 = tcpFlowInfo->tuple5;
            Tuple5::sort(&tuple5);
			if(filterTuple5Map.find(tuple5) == filterTuple5Map.end())
			{
				filterTuple5Map[tuple5] = true;
			}
        }
    }
    
    if((tcpFlowInfo->state & NS_TCP_DATA) != 0)
    {
        /*
        DEBUG_WRAP(DebugMessage("%s %u bytes:\t%s  %s\n", (tcpFlowInfo->dir == ORIG_TO_RESP ? "Send" : "Receive"), 
           dataLength, tcpFlowInfo->tuple5.toString().c_str(), (tcpFlowInfo->dir == ORIG_TO_RESP ? "==>" : "<==")););
        */
        
		// fprintf(stdout, "%s %u bytes:\t%s  %s\n", (tcpFlowInfo->dir == ORIG_TO_RESP ? "Send" : "Receive"), 
        //     dataLength, tcpFlowInfo->tuple5.toString().c_str(), (tcpFlowInfo->dir == ORIG_TO_RESP ? "==>" : "<=="));
                
        conn->newData(data, dataLength, tcpFlowInfo->dir);
    }
    
    if((tcpFlowInfo->state & NS_TCP_CLOSE) != 0 || (tcpFlowInfo->state & NS_TCP_RESET) != 0)
    {
        // DEBUG_WRAP(DebugMessage("Connection done:\t%s\n", tcpFlowInfo->tuple5.toString().c_str()););
		// fprintf(stderr, "Connection done:\t%s\n", tcpFlowInfo->tuple5.toString().c_str());
		conn->finish();
    }
    
    if((tcpFlowInfo->state & NS_TCP_TIMEOUT) != 0)
    {
        conn->finish();
    }
        
    return 0;
}
