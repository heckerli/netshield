#include "SignatureMatcher.h"

SignatureMatcher::SignatureMatcher()
{
	this->status = NOTINITIALIZED;
	memSize = sizeof(SignatureMatcher);
}

void SignatureMatcher::init(SignatureStorer *storer_)
{
	this->status = PENDING;
	this->storer = storer_;
	this->currentNode = storer->getRoot();
	this->currentContainedIdx = 1;
}

void SignatureMatcher::reset()
{
	this->status = PENDING;
	this->currentNode = storer->getRoot();
	this->currentContainedIdx = 1;
}

void SignatureMatcher::MatchCurrentNode(const char *keyBegin, const char *keyEnd, unsigned int signatureIdx, const unsigned int signLen)
{
	char* currentContainedString = this->currentNode->containedString;

	int currentContainedStrLen = 0;

	if (currentContainedString != NULL)			//match as most signature as possible in current node
	{
		currentContainedStrLen = (currentContainedString[0]&0x000000ff);
		while (signatureIdx < signLen && currentContainedIdx < currentContainedStrLen + 1
				&& keyBegin[signatureIdx] == currentContainedString[currentContainedIdx])
		{
			signatureIdx++;
			currentContainedIdx++;
		}
	}

	if (currentContainedIdx < currentContainedStrLen + 1)	//some character in current node is not matched
	{
		if (signatureIdx < signLen)		//some character in signature does not match in current node
		{
			status = NOTMATCH;
		}
		else
		{
			status = PENDING;
		}
		return;							//else, wait for the next part of signature
	}
	else			//all characters in current node are matched
	{
		if (signatureIdx < signLen)	//there is additional signature character
		{
			currentNode = currentNode->next[keyBegin[signatureIdx]&0x000000ff];
			if (currentNode != NULL)			//recursive matching
			{
				currentContainedIdx = 1;
				MatchCurrentNode(keyBegin, keyEnd, signatureIdx+1, signLen);
			}
			else		//signature is too long
			{
				status = NOTMATCH;
			}
		}
		else		//signature and current node finish matching in the same time
		{
			status = MATCH;
		}
	}
}

int SignatureMatcher::getStatus(void **param)
{
	if (status == MATCH && currentNode->data!=NULL)
	{
		*param = currentNode->data;
		reset();
		return 1;
	}
	else
	{
	    reset();
		return -1;
	}
}
