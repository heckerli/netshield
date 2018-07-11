#ifndef _PACKET_HANDLER_H_
#define _PACKET_HANDLER_H_

#include "Thread.h"
#include "Buffer.h"
#include "PacketAnalyzer.h"

class PacketHandler : public DataHandler
{
public:
    PacketHandler();
    ~PacketHandler();
};

#endif
