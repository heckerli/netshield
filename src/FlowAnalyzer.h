#ifndef _FLOW_ANALYZER_H_
#define _FLOW_ANALYZER_H_

#include "NetShield.h"
#include "Runnable.h"
#include "Buffer.h"
#include "FlowHandler.h"
#include "Analyzer.h"

class FlowAnalyzer : public Analyzer
{
public:
    FlowAnalyzer(FlowHandler * flow, FlowDir dir);
    virtual ~FlowAnalyzer();
    
    virtual INT32_T reset(FlowHandler * flow, FlowDir dir);

protected:
    FlowHandler * flow;
    FlowDir dir;
};

#endif
