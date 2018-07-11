#include "NetShield.h"
#include "Thread.h"
#include "Global.h"
#include "ThreadImplSingle.h"
#include "ThreadImplWin32Fiber.h"
#include "ThreadImplPth.h"
#include "Util.h"

Thread * Thread::mainThread = NULL;

Thread::Thread()
{
    // DEBUG_WRAP(DebugMessage("Thread::Thread()\n"););
    
    parent = NULL;
    
    if(reassembled->count == 1 || protocol.tlp == TLP_UDP)
    {
        threadImpl = new ThreadImplSingle();
    }
    else
    {
#ifdef WIN32
        threadImpl = new ThreadImplWin32Fiber();
#else
        threadImpl = new ThreadImplPth();
#endif
    }

    verify(threadImpl != NULL);
}

Thread::Thread(ThreadImpl * threadImpl)
: threadImpl(threadImpl)
{
    // DEBUG_WRAP(DebugMessage("Thread::Thread(ThreadImpl * threadImpl)\n"););
    
    parent = NULL;
}

Thread * Thread::getMainThread()
{
    if(Thread::mainThread == NULL)
    {
        if(reassembled->count == 1)
        {
            Thread::mainThread = new Thread(ThreadImplSingle::getMainThread());
        }
        else
        {
#ifdef WIN32
            Thread::mainThread = new Thread(ThreadImplWin32Fiber::getMainThread());
#else
            Thread::mainThread = new Thread(ThreadImplPth::getMainThread());
#endif
        }
        verify(Thread::mainThread);
    }
    
    return Thread::mainThread;
}

Thread::~Thread()
{
    // DEBUG_WRAP(DebugMessage("Thread::~Thread()\n"););
    
    verify(threadImpl != NULL);
    delete threadImpl;
}

Thread * Thread::setParent(Thread * thread)
{
    Thread * oldParent = this->parent;
    this->parent = thread;
    
    threadImpl->setParent(thread->threadImpl);
    
    return oldParent;
}

INT32_T Thread::yield(Thread * thread)
{
    // DEBUG_WRAP(DebugMessage("Thread::yield(Thread * thread)\n"););
    
    if(thread != NULL)
    {
	    return threadImpl->yield(thread->threadImpl);
	}
	else if(this->parent != NULL)
	{
	    return threadImpl->yield(this->parent->threadImpl);
	}
	else
	{
	    return -1;
	}
}

INT32_T Thread::reset()
{
    return threadImpl->reset();
}

Runnable * Thread::setRunnable(Runnable * runnable)
{
    return threadImpl->setRunnable(runnable);
}
