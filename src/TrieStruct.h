#ifndef _TRIE_STRUCT_H_
#define _TRIE_STRUCT_H_

#include "NetShield.h"
#include "trie/SignatureStorer.h"
#include "trie/SignatureMatcher.h"

#include <vector>

using namespace std;

template <class TrieData>
class TrieStruct
{
public:
    SignatureStorer trie;
    
    TrieStruct()
    {
        currentTrieStructTotalSize += trie.size();
    }
    
    ~TrieStruct()
    {
        currentTrieStructTotalSize -= trie.size();
    }
    
    INT32_T add(const char * key, const char * keyEnd, const TrieData & data)
    {
        currentTrieStructTotalSize -= trie.size();
        
        vector<TrieData> * vecTrieData = NULL;
        SignatureMatcher matcher;
        matcher.init(&trie);
        matcher.match(key, keyEnd);
        int result = matcher.getStatus((void **)(&vecTrieData));
        if(result < 0 || vecTrieData == NULL)
        {
            vecTrieData = new vector<TrieData>;
        }
        vecTrieData->push_back(data);
        
        trie.add(key, keyEnd, vecTrieData);
        
        currentTrieStructTotalSize += trie.size();

		return 0;
    }
};

#endif
