#include "NetShield.h"
#include "Global.h"
#include "DataHandler.h"
#include "Analyzer.h"

DataHandler::DataHandler()
{
    thread = new Thread();
    verify(thread != NULL);
    
    buffer = new Buffer();
    verify(buffer != NULL);
    
    buffer->setEventHandler(this);
    
    analyzer = NULL;
    
    threadToBeReset = false;
    neverRun = true;
}

INT32_T DataHandler::reset()
{
    analyzer->reset();
    buffer->skipFlow();
    buffer->reset();
    
    if(neverRun == false)
    {
        threadToBeReset = true;
    }

    return 0;
}

INT32_T DataHandler::finish()
{
    return analyzer->finish();
}

DataHandler::~DataHandler()
{
    delete thread;
    delete analyzer;
    delete buffer;
}

Thread * DataHandler::getThread()
{
    return thread;
}

Buffer * DataHandler::getBuffer()
{
    return buffer;
}

INT32_T DataHandler::onBufferEmpty(Buffer * buffer)
{
    // DEBUG_WRAP(DebugMessage("DataHandler::onBufferEmpty(Buffer * buffer)\n"););
    
    analyzer->beforeContextOut();
    
    thread->yield(NULL); // context is switched to parent.
    
    // context is back to this thread here.
    if(threadToBeReset == true)
    {
        threadToBeReset = false;
        thread->reset();
    }
    else
    {
        analyzer->afterContextIn();
    }
    
    return 0;
}

INT32_T DataHandler::newData(UINT8_T * data, UINT32_T dataLength)
{
    neverRun = false;
    buffer->newData(data, dataLength);
    thread->yield(thread);
    return 0;
}
