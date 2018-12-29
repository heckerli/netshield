#ifndef _BLOCK_LIST_H_
#define _BLOCK_LIST_H_

#include "NetShield.h"

#define DATA_SEGMENT_SIZE 1500

class Block
{
public:
    unsigned int dataLength;
    char data[DATA_SEGMENT_SIZE];
    Block * next;
};

class BlockList
{
public:
    Block * head;
    Block * tail;
    
    BlockList()
    {
        head = NULL;
        tail = NULL;
    }
    
    inline bool isEmpty()
    {
        return (head == NULL);
    }
    
    inline void empty()
    {
        head = NULL;
        tail = NULL;
    }
    
    inline Block * getFront()
    {
        if(head == NULL)
        {
            return NULL;
        }
        
        Block * retval = head;
        
        if(head == tail)
        {
            head = NULL;
            tail = NULL;
        }
        else
        {
            head = head->next;
        }
        
        return retval;
    }
    
    inline void pushBack(Block * block)
    {
        if(head == NULL)
        {
            head = block;
        }
        else
        {
            tail->next = block;
        }
        
        tail = block;
    }
    
    inline void pushBack(BlockList * l)
    {
        if(l->head == NULL)
        {
            return;
        }
        
        if(head == NULL)
        {
            head = l->head;
        }
        else
        {
            tail->next = l->head;
        }
        
        tail = l->tail;
    }
};

#endif