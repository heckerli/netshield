#ifndef _DATA_HANDLER_H_
#define _DATA_HANDLER_H_

#include "NetShield.h"
#include "Thread.h"
#include "Connection.h"
#include "Buffer.h"
#include "BufferEventHandler.h"

class Analyzer;

class DataHandler : public BufferEventHandler
{
public:
    DataHandler();
    virtual ~DataHandler();
    
    INT32_T reset();
    INT32_T finish();
    Thread * getThread();
    Buffer * getBuffer();
    INT32_T newData(UINT8_T * data, UINT32_T dataLength);
    
    virtual INT32_T onBufferEmpty(Buffer * buffer);

	Analyzer * analyzer;

protected:
    Thread * thread;
    bool threadToBeReset;
    bool neverRun;
    Buffer * buffer;
};

#endif
