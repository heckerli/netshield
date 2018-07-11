#ifndef _TRIE_MATCHER_H_
#define _TRIE_MATCHER_H_

#include "Global.h"
#include "TrieStruct.h"
#include "trie/SignatureMatcher.h"

template <class TrieData>
class TRIEState
{
public:
    bool isFinal;
    vector<TrieData> * dataVector;
    
    TRIEState()
    : isFinal(false), dataVector(NULL)
    {
    }
    
    TRIEState(const TRIEState & state)
    {
        this->isFinal = state.isFinal;
        this->dataVector = state.dataVector;
    }
    
    ~TRIEState()
    {
    }
    
    TRIEState & operator=(const TRIEState & state)
    {
        this->isFinal = state.isFinal;
        this->dataVector = state.dataVector;
        
        return *this;
    }
};

template <class TrieData>
class TrieMatcher
{
public:
    TrieMatcher()
    {
        this->trie = NULL;
        matcher = new SignatureMatcher();
        
        currentTrieMatcherTotalSize += sizeof(TrieMatcher);
        if(currentTrieMatcherTotalSize > maxTrieMatcherTotalSize)
        {
            maxTrieMatcherTotalSize = currentTrieMatcherTotalSize;
        }
    }
    
    TrieMatcher(TrieStruct<TrieData> * trie)
    {
        this->trie = trie;
        matcher = new SignatureMatcher();
        matcher->init(&(this->trie->trie));
        
        currentTrieMatcherTotalSize += sizeof(TrieMatcher);
        if(currentTrieMatcherTotalSize > maxTrieMatcherTotalSize)
        {
            maxTrieMatcherTotalSize = currentTrieMatcherTotalSize;
        }
    }
    
    ~TrieMatcher()
    {
        currentTrieMatcherTotalSize -= sizeof(TrieMatcher);
    }
    
    INT32_T init(TrieStruct<TrieData> * trie)
    {
        this->trie = trie;
        if(matcher == NULL)
        {
            matcher = new SignatureMatcher();
        }
        matcher->init(&(this->trie->trie));
        reset();

		return 0;
    }
    
    INT32_T reset()
    {
        if(matcher != NULL)
        {
            matcher->reset();
        }
        
        return 0;
    }
    
    INT32_T match(const UINT8_T * dataBegin, const UINT8_T * dataEnd)
    {
        if(matcher != NULL)
        {
            matcher->match((char *)dataBegin, (char *)dataEnd);
        }
        
        return 0;
    }
    
    INT32_T matchFromScratch(const UINT8_T * dataBegin, const UINT8_T * dataEnd)
    {
        reset();
        return match(dataBegin, dataEnd);
    }
    
    TRIEState<TrieData> getCurrentState()
    {
        TRIEState<TrieData> currentState;
        vector<TrieData> * vecTrieData = NULL;
        
        if(matcher != NULL)
        {
            int result = matcher->getStatus((void **)(&vecTrieData));
            
            if(result >= 0)
            {
                currentState.isFinal = true;
                currentState.dataVector = vecTrieData;
            }
        }
        
        return currentState;
    }

protected:
    TrieStruct<TrieData> * trie;
    SignatureMatcher * matcher;
};

#endif
