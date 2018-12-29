#ifndef _OBJECT_POOL_H_
#define _OBJECT_POOL_H_

#include <cassert>
#include <list>

#include "TCPReassembler.h"

template <class Object>
class ObjectPool
{
public:
    ObjectPool(unsigned int initSize)
    {
        for(unsigned int i = 0; i < initSize; i++)
        {
            Object * obj = new Object();
            verify(obj != NULL);
            objList.push_back(obj);
        }
    }
    
    ~ObjectPool()
    {
        typename std::list<Object *>::iterator it = objList.begin();
        while(it != objList.end())
        {
            Object * obj = *it;
            delete obj;
            *it = NULL;
            it++;
        }
        objList.clear();
    }
    
    Object * getObject()
    {
        if(objList.size() > 0)
        {
            Object * obj = objList.front();
            objList.pop_front();
            return obj;
        }
        else
        {
            Object * obj = new Object();
            verify(obj != NULL);
            return obj;
        }
    }
    
    int releaseObject(Object * obj)
    {
        assert(obj != NULL);
        
        objList.push_back(obj);
        return 0;
    }
    
protected:
    std::list<Object *> objList;
};

#endif
