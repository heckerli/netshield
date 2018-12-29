#ifndef _ANALYZER_H_
#define _ANALYZER_H_

#include "NetShield.h"
#include "Runnable.h"
#include "Buffer.h"
#include "FlowHandler.h"

class Analyzer : public Runnable
{
public:
    Analyzer();
    virtual ~Analyzer();
    
    virtual INT32_T reset();
    virtual INT32_T run() = 0;
    virtual INT32_T beforeContextOut();
    virtual INT32_T afterContextIn();
    virtual INT32_T finish();
    virtual Buffer * setBuffer(Buffer * buffer);

// protected:
    Buffer * buffer;
    BOOL_T matched;
};

#endif
