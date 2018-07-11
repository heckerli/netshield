#ifndef _DFA_MATCHER_H_
#define _DFA_MATCHER_H_

#include <vector>

#include "DFAStruct.h"

using namespace std;

/*
template <class DFAData>
class DFAState
{
public:
    // bool isStart;
    // bool isFinal;
    // bool isDead;
    const vector<DFAData> * dataVector;
    
    DFAState()
    : // isStart(false), isFinal(false), isDead(true),
      dataVector(NULL)
    {
    }
    
    DFAState(const DFAState & state)
    {
        // this->isStart = state.isStart;
        // this->isFinal = state.isFinal;
        // this->isDead  = state.isDead;
        this->dataVector = state.dataVector;
    }
    
    ~DFAState()
    {
    }
    
    DFAState & operator=(const DFAState & state)
    {
        // this->isStart = state.isStart;
        // this->isFinal = state.isFinal;
        // this->isDead  = state.isDead;
        this->dataVector = state.dataVector;
        
        return *this;
    }
};
*/

template <class DFAData>
class DFAMatcher
{
public:
    DFAMatcher()
    {
        this->dfa = NULL;
        current = 0;
        
        currentDFAMatcherTotalSize += sizeof(current);
        if(currentDFAMatcherTotalSize > maxDFAMatcherTotalSize)
        {
            maxDFAMatcherTotalSize = currentDFAMatcherTotalSize;
        }
    }
    
    DFAMatcher(DFAStruct<DFAData> * dfa)
    {
        this->dfa = dfa;
        current = dfa->dfa.startState;
        
        currentDFAMatcherTotalSize += sizeof(current);
        if(currentDFAMatcherTotalSize > maxDFAMatcherTotalSize)
        {
            maxDFAMatcherTotalSize = currentDFAMatcherTotalSize;
        }
    }
    
    ~DFAMatcher()
    {
        currentDFAMatcherTotalSize -= sizeof(current);
    }
    
    INT32_T init(DFAStruct<DFAData> * dfa)
    {
        this->dfa = dfa;
        return reset();
    }
    
    INT32_T reset()
    {
		if(dfa != NULL)
		{
			current = dfa->dfa.startState;
		}

        return 0;
    }
    
    INT32_T match(const UINT8_T * dataBegin, const UINT8_T * dataEnd,
                  void (*callback)(const DFAData & data, void * cbParam), void * cbParam)
    {
        const UINT8_T * p = dataBegin;
        while(p < dataEnd)
        {
            if(current < 0 || current >= dfa->dfa.stateNum)
            {
                return 0;
            }
            
            DFA::State * state = &(dfa->dfa.state[current]);
            
            if(state->isFinal == true)
            {
                vector<DFAStruct<DFAData>::DFADataWrapper> * vecDFADataWrapper = (vector<DFAStruct<DFAData>::DFADataWrapper> *)(state->data);
                if(vecDFADataWrapper != NULL)
                {
					vector<DFAStruct<DFAData>::DFADataWrapper>::const_iterator vecDFADataWrapperIt = vecDFADataWrapper->begin();
                    while(vecDFADataWrapperIt != vecDFADataWrapper->end())
                    {
                        if((*vecDFADataWrapperIt).hasDollar == false)
                        {
                            callback((*vecDFADataWrapperIt).data, cbParam);
                        }
                        
                        vecDFADataWrapperIt++;
                    }
                }
            }
            
            current = state->next[*p];
            
            p++;
        }
        
        return 0;
    }
    
    /*
    INT32_T matchFromScratch(const UINT8_T * dataBegin, const UINT8_T * dataEnd)
    {
        reset();
        return match(dataBegin, dataEnd);
    }
    */
    
    INT32_T getCurrentState(void (*callback)(const DFAData & data, void * cbParam), void * cbParam)
    {
        if(current < 0 || current >= dfa->dfa.stateNum)
        {
            return 0;
        }
        
        DFA::State * state = &(dfa->dfa.state[current]);
        
        // For the last final state, simply add all data into dfaDataVector no matter if it has '$' or not.
        // And it is not added into finalStateVector.
        if(state->isFinal == true)
        {
            vector<DFAStruct<DFAData>::DFADataWrapper> * vecDFADataWrapper = (vector<DFAStruct<DFAData>::DFADataWrapper> *)(state->data);
            if(vecDFADataWrapper != NULL)
            {
        		vector<DFAStruct<DFAData>::DFADataWrapper>::const_iterator vecDFADataWrapperIt = vecDFADataWrapper->begin();
                while(vecDFADataWrapperIt != vecDFADataWrapper->end())
                {
                    callback((*vecDFADataWrapperIt).data, cbParam);
                    
                    vecDFADataWrapperIt++;
                }
            }
        }

        return 0;
    }
    
protected:
    DFAStruct<DFAData> * dfa;
    INT32_T current;
};

#endif
