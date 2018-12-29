#ifndef _RUNNABLE_H_
#define _RUNNABLE_H_

#include "NetShield.h"

class Runnable
{
public:
    Runnable();
    virtual ~Runnable();
    virtual INT32_T run() = 0;
};

#endif
