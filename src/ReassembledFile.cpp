#include <cassert>

#include "NetShield.h"
#include "Global.h"
#include "ReassembledFile.h"
#include "Util.h"

ReassembledFile::ReassembledFile()
{
    scheduler = NULL;
    fp = NULL;
    
    if(protocol.tlp == TLP_TCP)
    {
        conn = new Connection();
        verify(conn);
    }
    else
    {
        conn = NULL;
    }
    
    bufLength = 1024 * 1024;
    buf = new UINT8_T[bufLength];
    
    contentLength = 0;
    
    verify(buf != NULL);
}

ReassembledFile::~ReassembledFile()
{
    close();
    
    if(conn != NULL)
    {
        delete conn;
    }
    
    delete []buf;
}

Scheduler * ReassembledFile::setScheduler(Scheduler * scheduler)
{
    Scheduler * oldScheduler = this->scheduler;
    this->scheduler = scheduler;
        
    return oldScheduler;
}

INT8_T ReassembledFile::open(const INT8_T * fileName)
{
    close();
    
    fp = fopen(fileName, "rb");
    verify(fp != NULL);
    
    fseek(fp, 0, SEEK_SET);
    UINT32_T fileStart = ftell(fp);
    fseek(fp, 0 ,SEEK_END);
    UINT32_T fileEnd = ftell(fp);
    UINT32_T fileSize = fileEnd - fileStart;
    contentLength = fileSize;
    
    fseek(fp, 0, SEEK_SET);
    
    if(fileSize > bufLength)
    {
        delete []buf;
        bufLength = fileSize;
        buf = new UINT8_T[bufLength];
        
        if(buf == NULL)
        {
            fprintf(stderr, "File %s is too large!\n", fileName);
            exit(0);
        }
    }
    
    UINT32_T fileReadSize = fread(buf, sizeof(UINT8_T), fileSize, fp);
    
    if(fileReadSize != fileSize)
    {
        fprintf(stderr, "The number of bytes read from file is not equal to file size!\n");
    }
    
    register UINT32_T size;
    register UINT8_T * p = buf;
    
    UINT32_T flowNum = 0;
    UINT32_T appLayerSize = 0;
    UINT8_T * contentEnd = buf + contentLength;
    while(p < contentEnd)
    {
        p++;
        size = *((UINT32_T *)p);
        p += 4;
        p += size;
        appLayerSize += size;
        flowNum++;
    }
    fprintf(stdout, protocol.tlp == TLP_TCP ? "Flow number: %u\n" : "Packet number: %u\n", flowNum);
    fprintf(stdout, "App layer size: %u bytes\n", appLayerSize);
    fprintf(stdout, protocol.tlp == TLP_TCP ? "Average flow size: %lf bytes\n" : "Average packet size: %lf bytes\n",
        ((double)appLayerSize)/((double)flowNum));
    
    return 0;
}

INT8_T ReassembledFile::close()
{
    if(fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    
    return 0;
}

INT32_T ReassembledFile::run()
{
    assert(fp != NULL);
    
    static TCPFlowInfo tcpFlowInfo;
    tcpFlowInfo.state = NS_TCP_ESTABLISHED | NS_TCP_DATA | NS_TCP_CLOSE;
    tcpFlowInfo.tuple5.origIP = 0;
    tcpFlowInfo.tuple5.origPort = 0;
    tcpFlowInfo.tuple5.respIP = 0;
    tcpFlowInfo.tuple5.respPort = 0;
    
    register UINT32_T size;
    register UINT8_T * p = buf;
    
    UINT8_T * contentEnd = buf + contentLength;
    while(p < contentEnd)
    {
        // UINT8_T direction = *p++;
        if(*p == 0)
        {
            tcpFlowInfo.dir = ORIG_TO_RESP;
        }
        else
        {
            tcpFlowInfo.dir = RESP_TO_ORIG;
        }
        
        p += 1;
    
        size = *((UINT32_T *)p);
        p += 4;
        
        if(size == 0)
        {
            continue;
        }
        
        if(protocol.tlp == TLP_TCP)
        {
            tcpFlowInfo.tuple5.protocol = 6; // TCP
			conn->tuple5 = tcpFlowInfo.tuple5;
            scheduler->newFlowData(&tcpFlowInfo, conn, p, size);
        }
        else if(protocol.tlp == TLP_UDP)
        {
            tcpFlowInfo.tuple5.protocol = 17; // UDP
            scheduler->newPacketData(&(tcpFlowInfo.tuple5), p, size);
        }

        p += size;
        
		tcpFlowInfo.tuple5.origIP++;
    }
    
    return 0;
}
