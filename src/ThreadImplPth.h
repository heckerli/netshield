#ifndef _THREAD_IMPL_PTH_H_
#define _THREAD_IMPL_PTH_H_

#ifndef WIN32

#include <pth.h>

#include "NetShield.h"
#include "ThreadImpl.h"

class ThreadImplPth : public ThreadImpl
{
public:
    ThreadImplPth();
    virtual ~ThreadImplPth();
    virtual INT32_T yield(ThreadImpl * threadImpl);
    
    static ThreadImplPth * getMainThread();

protected:
    ThreadImplPth(pth_t pth);
    static ThreadImplPth * mainThread;
    static VOID_T * pthProc(VOID_T * param);
    
    pth_t pth;
};

#endif

#endif
