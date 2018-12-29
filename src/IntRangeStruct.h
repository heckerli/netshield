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
protected:
    vector<INT32_T> keyVector;
    vector<Data> dataVector;
    
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
        currentIntRangeStructKeyTotalSize -= sizeof(INT32_T) * keyVector.size();
        currentIntRangeStructDataTotalSize -= sizeof(Data) * dataVector.size();
    }
    
    INT32_T add(INT32_T key, const Data & data)
    {
        if(keyVector.size() == 0)
        {
            keyVector.push_back(key);
            dataVector.push_back(data);
        }
        else
        {
            vector<INT32_T>::iterator keyIt = upper_bound(keyVector.begin(), keyVector.end(), key);
            vector<Data>::iterator dataIt = dataVector.begin() + distance(keyVector.begin(), keyIt);
            
            keyVector.insert(keyIt, key);
            dataVector.insert(dataIt, data);
        }
        
        pair<vector<INT32_T>::iterator, vector<INT32_T>::iterator> it;
        it = equal_range(keyVector.begin(), keyVector.end(), key);
        
        vector<Data>::iterator first = dataVector.begin() + distance(keyVector.begin(), it.first);
        vector<Data>::iterator last = dataVector.begin() + distance(keyVector.begin(), it.second);
        
        sort(first, last);
        
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
    
    INT32_T matchGt(INT32_T key, typename vector<Data>::const_iterator * first, typename vector<Data>::const_iterator * last)const
    {
        vector<INT32_T>::const_iterator keyIt = lower_bound(keyVector.begin(), keyVector.end(), key);
        
        *first = dataVector.begin();
        *last = dataVector.begin() + distance(keyVector.begin(), keyIt);
        
        return 0;
    }
    
    INT32_T matchEq(INT32_T key, typename vector<Data>::const_iterator * first, typename vector<Data>::const_iterator * last)const
    {
        pair<vector<INT32_T>::const_iterator, vector<INT32_T>::const_iterator> it;
        it = equal_range(keyVector.begin(), keyVector.end(), key);

        *first = dataVector.begin() + distance(keyVector.begin(), it.first);
        *last = dataVector.begin() + distance(keyVector.begin(), it.second);
        
        return 0;
    }
};

#endif
