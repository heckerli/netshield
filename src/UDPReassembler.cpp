#include "UDPReassembler.h"

FILE * UDPReassembler::outputFile = NULL;
UINT32_T UDPReassembler::instanceNum = 0;

UINT32_T UDPReassembler::appBytes = 0;
UINT32_T UDPReassembler::packetNum = 0;

UDPReassembler::UDPReassembler()
{
    UDPReassembler::instanceNum++;
}

UDPReassembler::~UDPReassembler()
{
    UDPReassembler::instanceNum--;

    if(UDPReassembler::instanceNum == 0)
    {
        fclose(UDPReassembler::outputFile);
        UDPReassembler::outputFile = NULL;
    }
}

INT32_T UDPReassembler::run()
{
    // DEBUG_WRAP(DebugMessage("UDPReassembler: 0x%.8X, run()\n", this););

    while(1)
    {            
        // DEBUG_WRAP(DebugMessage("UDPReassembler: 0x%.8X, PDU length = %d\n", this, length););
        
        UINT8_T * dataBegin = NULL;
        UINT32_T dataLength = 0;
        buffer->readAll(&dataBegin, &dataLength);
        
        FILE * fp = UDPReassembler::outputFile;
        char direction = 0;
        
        // 第一字节，0表示origin，1表示response
        fwrite(&direction, sizeof(char), 1, fp);
        
        // 接下来是一个整型变量，表示content长度
        fwrite(&dataLength, sizeof(UINT32_T), 1, fp);
        
        fwrite(dataBegin, sizeof(char), dataLength, fp);
        
        UDPReassembler::appBytes += dataLength;
        UDPReassembler::packetNum += 1;
    }

	return 0;
}

INT32_T UDPReassembler::setOutputFile(const char * fileName)
{
    if(UDPReassembler::outputFile == NULL)
    {
        UDPReassembler::outputFile = fopen(fileName, "wb");
        if(UDPReassembler::outputFile == NULL)
        {
            fprintf(stderr, "Cannot create file %s!\n", fileName);
            exit(0);
        }
    }
    
    return 0;
}
