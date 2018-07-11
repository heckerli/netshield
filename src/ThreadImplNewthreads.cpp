#include "NetShield.h"
#include "ThreadImplNewthreads.h"

#ifndef WIN32

ThreadImplNewthreads * ThreadImplNewthreads::mainThread = NULL;

ThreadImplNewthreads::ThreadImplNewthreads()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplNewthreads::ThreadImplNewthreads()\n"););
    
    if(ThreadImplNewthreads::mainThread == NULL)
    {
        ThreadImplNewthreads::getMainThread();
    }
    
    pth_attr_t attr = pth_attr_new();
    pth_attr_set(attr, PTH_ATTR_STACK_SIZE, NS_THREAD_STACK_SIZE);
    
    pth = pth_spawn(attr, pthProc, this);
}

ThreadImplNewthreads::ThreadImplNewthreads(pth_t pth)
: pth(pth)
{
    // DEBUG_WRAP(DebugMessage("ThreadImplNewthreads::ThreadImplNewthreads(pth_t pth)\n"););
}

ThreadImplNewthreads * ThreadImplNewthreads::getMainThread()
{
    if(ThreadImplNewthreads::mainThread == NULL)
    {
        init_newthreads(1, "ThreadImplNewthreads");
        
        ThreadImplNewthreads::mainThread = new ThreadImplNewthreads(pth_self());
        
        if (ThreadImplNewthreads::mainThread == NULL)
        {
            fprintf(stderr, "Obtain pth main thread error\n");
            exit(0);
        }
    }
    
    return ThreadImplNewthreads::mainThread;
}

ThreadImplNewthreads::~ThreadImplNewthreads()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplNewthreads::~ThreadImplNewthreads()\n"););
}

INT32_T ThreadImplNewthreads::yield(ThreadImpl * threadImpl)
{
    if(threadImpl != NULL)
    {
        pth_yield(((ThreadImplNewthreads *)threadImpl)->pth);
	    return 0;
	}
	else if(this->parent != NULL)
	{
	    pth_yield(((ThreadImplNewthreads *)parent)->pth);
	    return 0;
	}
	else
	{
	    return -1;
	}
}

#endif
