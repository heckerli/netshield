#include "NetShield.h"
#include "ThreadImplWin32Fiber.h"
#include "Param.h"

#ifdef WIN32

ThreadImplWin32Fiber * ThreadImplWin32Fiber::mainThread = NULL;
UINT32_T ThreadImplWin32Fiber::threadNum = 0;

ThreadImplWin32Fiber::ThreadImplWin32Fiber()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplWin32Fiber::ThreadImplWin32Fiber()\n"););
    
    if(ThreadImplWin32Fiber::mainThread == NULL)
    {
        ThreadImplWin32Fiber::getMainThread();
    }
    
    /*
    CreateFiberEx()需要的堆栈大小的单位是KB，
    第一个参数必须是0，第二个参数是栈大小，否则不正确。
    http://www.eggheadcafe.com/forumarchives/win32programmerkernel/Mar2006/post26109402.asp
    */
    fiber = CreateFiberEx(0, NS_THREAD_STACK_SIZE / 1024, 0, fiberProc, this);
    if(fiber == NULL)
    {
        fprintf(stderr, "CreateFiber error, not enough memory!\n");
        fprintf(stderr, "Current thread number is %u\n", ThreadImplWin32Fiber::threadNum);
        VOID_T displayStat();
        displayStat();
        
        exit(GetLastError());
    }
    
    isLongjmpBufSet = false;
    
    ThreadImplWin32Fiber::threadNum++;
}

ThreadImplWin32Fiber::ThreadImplWin32Fiber(LPVOID fiber)
: fiber(fiber)
{
    // DEBUG_WRAP(DebugMessage("ThreadImplWin32Fiber::ThreadImplWin32Fiber(LPVOID fiber)\n"););
    isLongjmpBufSet = false;
    
    ThreadImplWin32Fiber::threadNum++;
}

ThreadImplWin32Fiber * ThreadImplWin32Fiber::getMainThread()
{
    if(ThreadImplWin32Fiber::mainThread == NULL)
    {
        ThreadImplWin32Fiber::mainThread = new ThreadImplWin32Fiber(ConvertThreadToFiber(NULL));
        
        if (ThreadImplWin32Fiber::mainThread == NULL)
        {
            fprintf(stderr, "ConvertThreadToFiber error, code %d\n", GetLastError());
            exit(GetLastError());
        }
    }
    
    return ThreadImplWin32Fiber::mainThread;
}

ThreadImplWin32Fiber::~ThreadImplWin32Fiber()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplWin32Fiber::~ThreadImplWin32Fiber()\n"););
    
    DeleteFiber(fiber);
    ThreadImplWin32Fiber::threadNum--;
}

VOID CALLBACK ThreadImplWin32Fiber::fiberProc(PVOID param)
{
    ThreadImplWin32Fiber * thisFiber = (ThreadImplWin32Fiber *)param;
    
    while(1)
    {
        if(setjmp(thisFiber->longjmpBuf) == 0)
        {
            thisFiber->isLongjmpBufSet = true;
            thisFiber->runnable->run();
            thisFiber->yield(NULL);
        }
        else
        {
            thisFiber->isLongjmpBufSet = false;
        }
    }
}

INT32_T ThreadImplWin32Fiber::yield(ThreadImpl * threadImpl)
{
    if(threadImpl != NULL)
    {
        SwitchToFiber(((ThreadImplWin32Fiber *)threadImpl)->fiber);
	    return 0;
	}
	else if(this->parent != NULL)
	{
	    SwitchToFiber(((ThreadImplWin32Fiber *)parent)->fiber);
	    return 0;
	}
	else
	{
	    fprintf(stderr, "ThreadImplWin32Fiber::yield(ThreadImpl * threadImpl) parameter error!\n");
	    return -1;
	}
}

INT32_T ThreadImplWin32Fiber::reset()
{
    if(isLongjmpBufSet == true)
    {
        isLongjmpBufSet = false;
        longjmp(longjmpBuf, 1);
    }
    else
    {
        fprintf(stdout, "Cannot reset thread!\n");
    }

	return 0;
}

#endif
