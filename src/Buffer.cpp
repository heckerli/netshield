#include "NetShield.h"
#include "Buffer.h"

Buffer::Buffer()
{
    // DEBUG_WRAP(DebugMessage("Buffer::Buffer()\n"););
    
    eventHandler = NULL;
    byteCount = 0;
    
    dataBegin = NULL;
    dataEnd = NULL;
    dataPtr = NULL;
    
    recallPoint = 0;
    
    bSkipAll = false;
}

Buffer::~Buffer()
{
    // DEBUG_WRAP(DebugMessage("Buffer::~Buffer()\n"););
}

BufferEventHandler * Buffer::setEventHandler(BufferEventHandler * eventHandler)
{
    BufferEventHandler * oldEventHandler = this->eventHandler;
    this->eventHandler = eventHandler;
        
    return oldEventHandler;
}
