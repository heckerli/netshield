#ifndef _THREAD_IMPL_H_
#define _THREAD_IMPL_H_

#include "NetShield.h"
#include "Runnable.h"

class ThreadImpl
{
public:
    ThreadImpl();
    
    virtual ~ThreadImpl();
    virtual Runnable * setRunnable(Runnable * runnable);
    virtual ThreadImpl * setParent(ThreadImpl * threadImpl);
    virtual INT32_T yield(ThreadImpl * threadImpl) = 0;
    virtual INT32_T reset() = 0;

protected:
    ThreadImpl * parent;
    Runnable * runnable;
};

#endif
