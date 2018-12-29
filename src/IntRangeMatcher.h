#ifndef _INT_RANGE_MATCHER_H_
#define _INT_RANGE_MATCHER_H_

#include "IntRangeStruct.h"

template <class Data>
class IntRangeMatcher
{
public:
    IntRangeMatcher()
    {
        length = 0;
        this->intRangeStruct = NULL;
        
        currentIntRangeMatcherTotalSize += sizeof(length);
        if(currentIntRangeMatcherTotalSize > maxIntRangeMatcherTotalSize)
        {
            maxIntRangeMatcherTotalSize = currentIntRangeMatcherTotalSize;
        }
    }
    
    IntRangeMatcher(const IntRangeStruct<Data> * intRangeStruct)
    {
        length = 0;
        this->intRangeStruct = intRangeStruct;
        
        currentIntRangeMatcherTotalSize += sizeof(length);
        if(currentIntRangeMatcherTotalSize > maxIntRangeMatcherTotalSize)
        {
            maxIntRangeMatcherTotalSize = currentIntRangeMatcherTotalSize;
        }
    }
    
    ~IntRangeMatcher()
    {
        currentIntRangeMatcherSize -= sizeof(length);
    }
    
    INT32_T init(const IntRangeStruct<Data> * intRangeStruct)
    {
        length = 0;
        this->intRangeStruct = intRangeStruct;

		return 0;
    }
    
    INT32_T reset()
    {
        length = 0;
		return 0;
    }
    
    INT32_T match(INT32_T key)
    {
        length += key;
        return 0;
    }
    
    INT32_T matchFromScratch(INT32_T key)
    {
        length = key;
        return 0;
    }
    
    INT32_T getGtCurrentState(typename vector<typename Data>::const_iterator * first,
                              typename vector<typename Data>::const_iterator * last)
    {
        intRangeStruct->matchGt(length, first, last);
        return 0;
    }
    
    INT32_T getEqCurrentState(typename vector<typename Data>::const_iterator * first,
                              typename vector<typename Data>::const_iterator * last)
    {
        intRangeStruct->matchEq(length, first, last);
        return 0;
    }
    
protected:
    const IntRangeStruct<Data> * intRangeStruct;
    INT32_T length; 
};

#endif
