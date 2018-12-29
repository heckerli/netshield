#include "NetShield.h"
#include "FlowAnalyzer.h"

FlowAnalyzer::FlowAnalyzer(FlowHandler * flow, FlowDir dir)
{
    // DEBUG_WRAP(DebugMessage("FlowAnalyzer::FlowAnalyzer()\n"););
    
    this->flow = flow;
    this->dir = dir;
}

FlowAnalyzer::~FlowAnalyzer()
{
    // DEBUG_WRAP(DebugMessage("FlowAnalyzer::~FlowAnalyzer()\n"););
}

INT32_T FlowAnalyzer::reset(FlowHandler * flow, FlowDir dir)
{
    Analyzer::reset();
    
    this->flow = flow;
    this->dir = dir;
    return 0;
}
