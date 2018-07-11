#ifndef _THREAD_IMPL_WIN32_FIBER_H_
#define _THREAD_IMPL_WIN32_FIBER_H_

#ifdef WIN32

#include <winsock2.h>
#include <windows.h>
#include <setjmp.h>

#include "NetShield.h"
#include "ThreadImpl.h"

class ThreadImplWin32Fiber : public ThreadImpl
{
public:
    ThreadImplWin32Fiber();
    virtual ~ThreadImplWin32Fiber();
    virtual INT32_T yield(ThreadImpl * threadImpl);
    virtual INT32_T reset();
    
    static ThreadImplWin32Fiber * getMainThread();

protected:
    ThreadImplWin32Fiber(LPVOID fiber);
    static ThreadImplWin32Fiber * mainThread;
    
    static VOID CALLBACK fiberProc(PVOID param);
    LPVOID fiber;
    jmp_buf longjmpBuf;
    bool isLongjmpBufSet;
    
    static UINT32_T threadNum;
};

#endif

#endif
