#include "NetShield.h"
#include "Analyzer.h"

Analyzer::Analyzer()
{
    // DEBUG_WRAP(DebugMessage("Analyzer::Analyzer()\n"););
    
    buffer = NULL;
    matched = false;
}

Analyzer::~Analyzer()
{
    // DEBUG_WRAP(DebugMessage("Analyzer::~Analyzer()\n"););
}

INT32_T Analyzer::reset()
{
    matched = false;
    return 0;
}

INT32_T Analyzer::beforeContextOut()
{
    return 0;
}

INT32_T Analyzer::afterContextIn()
{
    return 0;
}

INT32_T Analyzer::finish()
{
    return 0;
}

Buffer * Analyzer::setBuffer(Buffer * buffer)
{
    Buffer * oldBuffer = this->buffer;
    this->buffer = buffer;
        
    return oldBuffer;
}
