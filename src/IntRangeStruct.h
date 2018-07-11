#ifndef _INT_RANGE_STRUCT_H_
#define _INT_RANGE_STRUCT_H_

#include <vector>
#include <algorithm>

#include "NetShield.h"
#include "Global.h"

using namespace std;

template <class Data>
class IntRangeStruct
{
public:
    class Pair
    {
    public:
        INT32_T key;
        Data data;
        
        Pair()
        {
        }
        
        Pair(const INT32_T & key)
        : key(key), data()
        {
        }
        
        Pair(const INT32_T & key, const Data & data)
        : key(key), data(data)
        {
        }
        
        Pair(const Pair & pair)
        : key(pair.key), data(pair.data)
        {
        }
        
        ~Pair()
        {
        }
        
        Pair & operator=(const Pair & pair)
        {
            this->key = pair.key;
            this->data = pair.data;
            
            return *this;
        }
        
        bool operator<(const Pair & pair)const
        {
            return this->key < pair.key;
        }
    };
    
protected:
    vector<Pair> pairVector;
    
public:
    IntRangeStruct()
    {
        currentIntRangeStructNum++;
        if(currentIntRangeStructNum > maxIntRangeStructNum)
        {
            maxIntRangeStructNum = currentIntRangeStructNum;
        }
    }
    
    ~IntRangeStruct()
    {
        currentIntRangeStructNum--;
        currentIntRangeStructKeyTotalSize -= sizeof(INT32_T) * pairVector.size();
        currentIntRangeStructDataTotalSize -= sizeof(Data) * pairVector.size();
    }
    
    INT32_T add(INT32_T key, const Data & data)
    {
        pairVector.push_back(Pair(key, data));
        sort(pairVector.begin(), pairVector.end());
        
        currentIntRangeStructKeyTotalSize += sizeof(key);
        if(currentIntRangeStructKeyTotalSize > maxIntRangeStructKeyTotalSize)
        {
            maxIntRangeStructKeyTotalSize = currentIntRangeStructKeyTotalSize;
        }
        
        currentIntRangeStructDataTotalSize += sizeof(data);
        if(currentIntRangeStructDataTotalSize > maxIntRangeStructDataTotalSize)
        {
            maxIntRangeStructDataTotalSize = currentIntRangeStructDataTotalSize;
        }
        
        return 0;
    }
    
    INT32_T matchGt(INT32_T key, typename vector<Pair>::const_iterator * first, typename vector<Pair>::const_iterator * last)const
    {
        *first = pairVector.begin();
        *last = lower_bound(pairVector.begin(), pairVector.end(), Pair(key));
        
        return 0;
    }
};

#endif
