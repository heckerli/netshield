#ifndef _THREAD_IMPL_SINGLE_H_
#define _THREAD_IMPL_SINGLE_H_

#include <setjmp.h>

#include "NetShield.h"
#include "ThreadImpl.h"

class ThreadImplSingle : public ThreadImpl
{
public:
    ThreadImplSingle();
    virtual ~ThreadImplSingle();
    virtual INT32_T yield(ThreadImpl * threadImpl);
    virtual INT32_T reset();
    
    static ThreadImplSingle * getMainThread();

protected:
    static ThreadImplSingle * mainThread;
    jmp_buf buf;
};

#endif
