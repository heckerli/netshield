#ifndef _MEM_POOL_H_
#define _MEM_POOL_H_

#include "TCPReassembler.h"
#include "BlockList.h"

class MemPool
{
public:
    MemPool(unsigned int initNum)
    {
        this->initNum = initNum;
        
        alloc(initNum);
    }
    
    inline Block * get()
    {      
        if(freeList.isEmpty() == true)
        {
            alloc(initNum);
        }
        
        return freeList.getFront();
    }
    
    inline void release(Block * block)
    {
        freeList.pushBack(block);
    }
    
    inline void release(BlockList * l)
    {
        freeList.pushBack(l);
    }
    
protected:
    unsigned int initNum;
    BlockList freeList;
    
    inline void alloc(unsigned int num)
    {
        Block * block = new Block[num];
        verify(block);
        
        for(unsigned int i = 0; i < num; i++)
        {
            freeList.pushBack(&(block[i]));
        }
    }
};

#endif