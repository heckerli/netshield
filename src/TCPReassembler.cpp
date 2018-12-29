#include "TCPReassembler.h"

FILE * TCPReassembler::outputFile = NULL;
UINT32_T TCPReassembler::instanceNum = 0;
MemPool * TCPReassembler::memPool = NULL;

UINT32_T TCPReassembler::appBytes = 0;
UINT32_T TCPReassembler::flowNum = 0;

TCPReassembler::TCPReassembler(FlowHandler * flow, FlowDir dir)
: FlowAnalyzer(flow, dir)
{
    TCPReassembler::instanceNum++;
    
    if(TCPReassembler::memPool == NULL)
    {
        TCPReassembler::memPool = new MemPool(500000);
        verify(TCPReassembler::memPool);
    }
}

TCPReassembler::~TCPReassembler()
{
    finish();
    TCPReassembler::instanceNum--;

    if(TCPReassembler::instanceNum == 0)
    {
        fclose(TCPReassembler::outputFile);
        TCPReassembler::outputFile = NULL;
        
        delete TCPReassembler::memPool;
        TCPReassembler::memPool = NULL;
    }
}

INT32_T TCPReassembler::reset(FlowHandler * flow, FlowDir dir)
{
    finish();
    FlowAnalyzer::reset(flow, dir);
    
    return 0;
}

INT32_T TCPReassembler::setOutputFile(const char * fileName)
{
    if(TCPReassembler::outputFile == NULL)
    {
        TCPReassembler::outputFile = fopen(fileName, "wb");
        if(TCPReassembler::outputFile == NULL)
        {
            fprintf(stderr, "Cannot create file %s!\n", fileName);
            exit(0);
        }
    }
    
    return 0;
}

INT32_T TCPReassembler::run()
{
    while(1)
    {
        UINT8_T * dataBegin = NULL;
        UINT32_T dataLength = 0;
        buffer->readAll(&dataBegin, &dataLength);
        if(dataBegin != NULL && dataLength > 0)
        {
            addToList(dataBegin, dataLength, &blockList);
        }
    }
    
    return 0;
}

INT32_T TCPReassembler::finish()
{
    if(blockList.isEmpty() == false)
    {
        writeToFile(TCPReassembler::outputFile, dir, &blockList);
        memPool->release(&blockList);
        blockList.empty();
        
        TCPReassembler::flowNum++;
    }
    
    return FlowAnalyzer::finish();
}

void TCPReassembler::addToList(UINT8_T * data, UINT32_T dataLength, BlockList * l)
{
    while(dataLength > 0)
    {
        Block * block = memPool->get();
        
        if(dataLength > DATA_SEGMENT_SIZE)
        {
            block->dataLength = DATA_SEGMENT_SIZE;
            memcpy(block->data, data, DATA_SEGMENT_SIZE);
            dataLength -= DATA_SEGMENT_SIZE;
            data += DATA_SEGMENT_SIZE;
        }
        else
        {
            block->dataLength = dataLength;
            memcpy(block->data, data, dataLength);
            dataLength -= dataLength;
            data += dataLength;
        }
        
        l->pushBack(block);
    }
}

void TCPReassembler::writeToFile(FILE * fp, FlowDir dir, BlockList * l)
{
    Block * block = l->head;
    if(block == NULL)
    {
        return;
    }
    
    l->tail->next = NULL;
    
    unsigned int length = 0;
    while(block != NULL)
    {
        length += block->dataLength;
        block = block->next;
    }
    
    char direction = 0;
    if(dir == RESP_TO_ORIG)
    {
        direction = 1;
    }
    
    // 第一字节，0表示origin，1表示response
    fwrite(&direction, sizeof(char), 1, fp);
    
    // 接下来是一个整型变量，表示content长度
    fwrite(&length, sizeof(unsigned int), 1, fp);
    
    block = l->head;
    while(block != NULL)
    {
        // 接下来是content
        fwrite(block->data, sizeof(char), block->dataLength, fp);
        
        block = block->next;
    }
    
    TCPReassembler::appBytes += length;
}
