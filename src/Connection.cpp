#include "NetShield.h"
#include "Connection.h"
#include "FlowHandler.h"

Connection::Connection()
{
    this->thread = NULL;
    
    this->upFlow = new FlowHandler(this, ORIG_TO_RESP);
    verify(upFlow != NULL);
    
    this->downFlow = new FlowHandler(this, RESP_TO_ORIG);
    verify(downFlow != NULL);
    
    accMatchedNum = 0;
}

Connection::~Connection()
{
    delete upFlow;
    delete downFlow;
}

INT32_T Connection::reset(const Tuple5 & tuple5, Thread * thread)
{
    this->thread = thread;
    
    upFlow->reset(this, ORIG_TO_RESP);
    upFlow->getThread()->setParent(thread);
    
    downFlow->reset(this, RESP_TO_ORIG);
    downFlow->getThread()->setParent(thread);
    
    this->tuple5 = tuple5;
    
    accMatchedNum = 0;
    
    return 0;
}

INT32_T Connection::finish()
{
    upFlow->finish();
    downFlow->finish();

	return 0;
}

INT32_T Connection::newData(UINT8_T * data, UINT32_T dataLength, FlowDir dir)
{
    FlowHandler * flow = NULL;
    if(dir == ORIG_TO_RESP)
    {
        flow = upFlow;
    }
    else
    {
        flow = downFlow;
    }
    
    flow->newData(data, dataLength);
        
    return 0;
}
