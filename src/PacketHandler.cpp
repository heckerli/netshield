#include "Global.h"
#include "PacketHandler.h"
#include "UDPReassembler.h"
#include "DNSAnalyzer.h"

PacketHandler::PacketHandler()
{
    if(udpReassembly->count > 0)
    {
        UDPReassembler * udpReassembler = new UDPReassembler();
        verify(udpReassembler);
        udpReassembler->setOutputFile(writeFile->filename[0]);
        analyzer = udpReassembler;
    }
    else
    {
        analyzer = new DNSAnalyzer();
    }
    verify(analyzer);
    
    analyzer->setBuffer(buffer);
    
    thread->setRunnable(analyzer);
}

PacketHandler::~PacketHandler()
{
}
