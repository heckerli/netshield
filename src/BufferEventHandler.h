#ifndef _BUFFER_EVENT_HANDLER_H_
#define _BUFFER_EVENT_HANDLER_H_

#include "NetShield.h"

class Buffer;

class BufferEventHandler
{
public:
    BufferEventHandler();
    virtual ~BufferEventHandler();
    
    virtual INT32_T onBufferEmpty(Buffer * buffer) = 0;
};

#endif
