#include "NetShield.h"
#include "ThreadImplPth.h"

#ifndef WIN32

ThreadImplPth * ThreadImplPth::mainThread = NULL;

ThreadImplPth::ThreadImplPth()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplPth::ThreadImplPth()\n"););
    
    if(ThreadImplPth::mainThread == NULL)
    {
        ThreadImplPth::getMainThread();
    }
    
    pth_attr_t attr = pth_attr_new();
    pth_attr_set(attr, PTH_ATTR_STACK_SIZE, NS_THREAD_STACK_SIZE);
    
    pth = pth_spawn(attr, pthProc, this);
}

ThreadImplPth::ThreadImplPth(pth_t pth)
: pth(pth)
{
    // DEBUG_WRAP(DebugMessage("ThreadImplPth::ThreadImplPth(pth_t pth)\n"););
}

ThreadImplPth * ThreadImplPth::getMainThread()
{
    if(ThreadImplPth::mainThread == NULL)
    {
        pth_init();
        
        ThreadImplPth::mainThread = new ThreadImplPth(pth_self());
        
        if (ThreadImplPth::mainThread == NULL)
        {
            fprintf(stderr, "Obtain pth main thread error\n");
            exit(0);
        }
    }
    
    return ThreadImplPth::mainThread;
}

ThreadImplPth::~ThreadImplPth()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplPth::~ThreadImplPth()\n"););
    
    pth_abort(pth);
}

VOID_T * ThreadImplPth::pthProc(VOID_T * param)
{
    ThreadImplPth * thisPth = (ThreadImplPth *)param;
    
    thisPth->runnable->run();
    
    thisPth->yield(NULL);
}

INT32_T ThreadImplPth::yield(ThreadImpl * threadImpl)
{
    if(threadImpl != NULL)
    {
        pth_yield(((ThreadImplPth *)threadImpl)->pth);
	    return 0;
	}
	else if(this->parent != NULL)
	{
	    pth_yield(((ThreadImplPth *)parent)->pth);
	    return 0;
	}
	else
	{
	    return -1;
	}
}

#endif
