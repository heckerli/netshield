#ifndef _THREAD_IMPL_NEWTHREADS_H_
#define _THREAD_IMPL_NEWTHREADS_H_

#ifndef WIN32

#include "NetShield.h"
#include "newthreads/newthreads.h"
#include "ThreadImpl.h"

class ThreadImplNewthreads : public ThreadImpl
{
public:
    ThreadImplNewthreads();
    virtual ~ThreadImplNewthreads();
    virtual INT32_T yield(ThreadImpl * threadImpl);
    
    static ThreadImplNewthreads * getMainThread();

protected:
    ThreadImplNewthreads(pth_t pth);
    static ThreadImplNewthreads * mainThread;
    static VOID_T * threadProc(VOID_T * param);
};

#endif

#endif
