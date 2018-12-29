#include "NetShield.h"
#include "ThreadImplSingle.h"

ThreadImplSingle * ThreadImplSingle::mainThread = NULL;

ThreadImplSingle::ThreadImplSingle()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplSingle::ThreadImplSingle()\n"););
}

ThreadImplSingle * ThreadImplSingle::getMainThread()
{
    return ThreadImplSingle::mainThread;
}

ThreadImplSingle::~ThreadImplSingle()
{
    // DEBUG_WRAP(DebugMessage("ThreadImplSingle::~ThreadImplSingle()\n"););
}

INT32_T ThreadImplSingle::yield(ThreadImpl * threadImpl)
{
    if(threadImpl == this)
    {
        if(setjmp(this->buf) == 0)
        {
            this->runnable->run();
            return 0;
        }

	    return 1;
	}
	else if(threadImpl == parent)
	{
	    longjmp(this->buf, 1);
	    return 1;
	}
	else
	{
	    return -1;
	}
}

INT32_T ThreadImplSingle::reset()
{
    return 0;
}
