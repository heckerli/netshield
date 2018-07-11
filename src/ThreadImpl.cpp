#include "NetShield.h"
#include "ThreadImpl.h"

ThreadImpl::ThreadImpl()
{
    // DEBUG_WRAP(DebugMessage("ThreadImpl::ThreadImpl()\n"););
    
    parent = NULL;
    runnable = NULL;
}

ThreadImpl::~ThreadImpl()
{
    // DEBUG_WRAP(DebugMessage("ThreadImpl::~ThreadImpl()\n"););
}

Runnable * ThreadImpl::setRunnable(Runnable * runnable)
{
    Runnable * oldRunnable = this->runnable;
    this->runnable = runnable;
    
    return oldRunnable;
}

ThreadImpl * ThreadImpl::setParent(ThreadImpl * threadImpl)
{
    ThreadImpl * oldParent = this->parent;
    this->parent = threadImpl;
    
    return oldParent;
}
