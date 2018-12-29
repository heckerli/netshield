#ifndef _FLOW_HANDLER_H_
#define _FLOW_HANDLER_H_

#include "NetShield.h"
#include "DataHandler.h"
#include "Connection.h"

class FlowHandler : public DataHandler
{
public:
    FlowHandler(Connection * conn, FlowDir dir);
    virtual ~FlowHandler();
    
    INT32_T reset(Connection * conn, FlowDir dir);
    Connection * getConnection();
    
protected:
    Connection * conn;
    FlowDir dir;
};

#endif
