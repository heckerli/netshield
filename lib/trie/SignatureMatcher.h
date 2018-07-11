#ifndef SIGNATUREMATCHER_H
#define SIGNATUREMATCHER_H

#include "node.h"
#include "SignatureStorer.h"

#define NOTINITIALIZED 0x00 
#define PENDING 0x01
#define MATCH 0x02
#define NOTMATCH 0x03

class SignatureMatcher
{
private:
	SignatureStorer* storer;
	Node* currentNode;
	unsigned char currentContainedIdx;
	unsigned char status;
	unsigned int memSize;
	void MatchCurrentNode(const char *keyBegin, const char *keyEnd, unsigned int signatureIdx, const unsigned int signLen);
public:
    SignatureMatcher();
    
    // Setup the corresponding trie struct for the matcher to use in the following matching.
    // Note that the matcher should support multiple times initialization during it's lifetime.
    // After initialized, the matcher should be in the initial state, just as reset() function has just been called.
    void init(SignatureStorer * storer_);
    
    // Reset the status of the matcher into initial state, just as no character has been inputted 
    // and the matcher is in the root node of the trie.
    // This function may be called at any time.
    void reset();
    
    // Match every character in the char array of the key. Note that this function is an incremental matching,
    // which means that a whole key may be splitted into several char arrays and matched by calling this function several times.
    // So the matcher must maintain intermediate states during the matching process.
    inline void match(const char *keyBegin, const char *keyEnd)
	{
		if (status == PENDING || status == MATCH)
		{
			MatchCurrentNode(keyBegin, keyEnd, 0, keyEnd - keyBegin);
		}
		else if (status == NOTINITIALIZED)
		{
			status = NOTMATCH;
		}
	}
    
    // When this function is called, the matcher knows that the key to be matched has been fully inputted,
    // and will take the latest intermediate state maintained in the matcher as the final state.
    // If the final state is an acceptable state, then the function should put the corresponding data of the matched key
    // into the variable pointed by param and return a positive value; otherwise return a negative value and do not 
    // change the value of the variable pointed by param.
    int getStatus(void ** param);

	inline unsigned int size()
	{
		return memSize;
	}
};

#endif