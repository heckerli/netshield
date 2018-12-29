#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "NetShield.h"
#include "Thread.h"

class FlowHandler;

class Connection
{
public:
    Connection();
    virtual ~Connection();
    
    INT32_T reset(const Tuple5 & tuple5, Thread * thread);
    INT32_T finish();
    INT32_T newData(UINT8_T * data, UINT32_T dataLength, FlowDir dir);
    
    UINT32_T accMatchedNum; // The accumulated number of matched rules

	Tuple5 tuple5;

	FlowHandler * upFlow;      // ORIG_TO_RESP
    FlowHandler * downFlow;    // RESP_TO_ORIG
    
protected:
    Thread * thread;
};

#endif
