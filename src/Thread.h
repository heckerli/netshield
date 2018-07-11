#ifndef _THREAD_H_
#define _THREAD_H_

#include "NetShield.h"
#include "ThreadImpl.h"

class Thread
{
public:
    Thread();
    ~Thread();
    Runnable * setRunnable(Runnable * runnable);
    Thread * setParent(Thread * thread);
    INT32_T yield(Thread * thread);
    INT32_T reset();
    
    static Thread * getMainThread();
    
protected:
    Thread * parent;
    ThreadImpl * threadImpl;
    
    Thread(ThreadImpl * threadImpl);
    static Thread * mainThread;
};

#endif
