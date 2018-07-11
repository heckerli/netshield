#include "NetShield.h"
#include "Global.h"
#include "FlowHandler.h"
#include "HTTPAnalyzer.h"
#include "DCERPCAnalyzer.h"
#include "TCPReassembler.h"

FlowHandler::FlowHandler(Connection * conn, FlowDir dir)
{
    this->conn = conn;
    this->dir = dir;
    
    if(tcpReassembly->count > 0)
    {
        TCPReassembler * tcpReassembler = new TCPReassembler(this, this->dir);
        verify(tcpReassembler);
        tcpReassembler->setOutputFile(writeFile->filename[0]);
        analyzer = tcpReassembler;
    }
    else if(protocol == PROTOCOL_DCE_RPC)
    {
        analyzer = new DCERPCAnalyzer(this, this->dir);
    }
    else
    {
        // analyzer = new HTTPAnalyzer(this, this->dir);
        analyzer = new HTTPAnalyzer(this, this->dir, (usePac->count > 0));
    }
    verify(analyzer != NULL);
    
    analyzer->setBuffer(buffer);
    
    thread->setRunnable(analyzer);
}

INT32_T FlowHandler::reset(Connection * conn, FlowDir dir)
{
    DataHandler::reset();
    
    this->conn = conn;
    this->dir = dir;
    
    ((FlowAnalyzer *)analyzer)->reset(this, this->dir);

    return 0;
}

FlowHandler::~FlowHandler()
{
}

Connection * FlowHandler::getConnection()
{
    return conn;
}
