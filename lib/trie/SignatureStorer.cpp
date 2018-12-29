#include <string.h>
#include <assert.h>
#include "SignatureStorer.h"

SignatureStorer::SignatureStorer()
{
	currentNode = NULL;
	memSize = /*sizeof(Node) + sizeof(Node*)*/sizeof(SignatureStorer);
}

void SignatureStorer::AddCurrentNode(const char* keyBegin, const char* keyEnd, int signatureIdx, void* data)
{
	char* currentContainedString = currentNode->containedString;
	char* newContainedStr;
	int signLen = keyEnd - keyBegin;

	int currentContainedIdx = 1;
	int currentContainedStrLen = 0;

	if (currentContainedString != NULL)		//match signature with string contained in current node
	{
		currentContainedStrLen = (currentContainedString[0]&0x000000ff);
		while (signatureIdx < signLen  && currentContainedIdx < currentContainedStrLen + 1
				&& keyBegin[signatureIdx] == currentContainedString[currentContainedIdx])
		{
			signatureIdx++;
			currentContainedIdx++;
		}
	}

	if (currentContainedIdx < currentContainedStrLen+1)	//in case the current node should split
	{
		Node* newChild = new Node();
		memSize+=sizeof(Node);
		newChild->father = currentNode;			//Set child node
		if (currentContainedIdx < currentContainedStrLen)
		{
			newContainedStr = new char[currentContainedStrLen - currentContainedIdx + 1];
			memSize+=(currentContainedStrLen - currentContainedIdx + 1);
			newContainedStr[0] = (char)(currentContainedStrLen - currentContainedIdx);
			memcpy(newContainedStr + 1, currentContainedString+currentContainedIdx + 1, currentContainedStrLen - currentContainedIdx);
			newChild->containedString = newContainedStr;
		}
		newChild->data = currentNode->data;
		memcpy(newChild->next, currentNode->next, 256*sizeof(Node*));
		
		int i;
		for (i = 0; i<(((int)currentContainedString[currentContainedIdx])&0x000000ff) ; i++)	//Set current node
			currentNode->next[i] = NULL;
		currentNode->next[i] = newChild;
		i++;
		for (; i<=255 ; i++)
			currentNode->next[i] = NULL;;

		if (currentContainedIdx > 1)
		{
			currentContainedString[0] = currentContainedIdx-1;
		}
		else if (currentContainedString!=NULL)
		{
			memSize-=(((currentNode->containedString[0])&0x000000ff) + 1);
			delete[] currentNode->containedString;
			currentNode->containedString = NULL;
		}

		if (signatureIdx < signLen)		//create child node to contain the signature
		{
			currentNode->data = NULL;

			Node* newChild = new Node();
			memSize+=sizeof(Node);
			newChild->father = currentNode;
			if (signLen - signatureIdx > 1)
			{
				newContainedStr = new char[signLen - signatureIdx];
				memSize+=(signLen - signatureIdx);
				newContainedStr[0] = (char)(signLen - signatureIdx - 1);
				memcpy(newContainedStr + 1, keyBegin + signatureIdx + 1, signLen - signatureIdx - 1);
				newChild->containedString = newContainedStr;
			}
			newChild->data = data;
			currentNode->next[keyBegin[signatureIdx]&0x000000ff] = newChild;		
		}
		else	
		{
			currentNode->data = data;
		}
	}
	else		//whole string contained in current node is matched to signature
	{
		if (signatureIdx < signLen)
		{
			if (currentNode->next[keyBegin[signatureIdx]&0x000000ff] != NULL)	//add signature in child node
			{
				currentNode = currentNode->next[keyBegin[signatureIdx]&0x000000ff];
				AddCurrentNode(keyBegin, keyEnd, signatureIdx+1, data);
			}
			else			//create child node to contain the signature
			{
				Node* newChild = new Node();
				memSize+=sizeof(Node);
				newChild->father = currentNode;
				if (signLen - signatureIdx > 1)
				{
					newContainedStr = new char[signLen - signatureIdx];
					memSize+=(signLen - signatureIdx);
					newContainedStr[0] = (char)(signLen - signatureIdx - 1);
					memcpy(newContainedStr + 1, keyBegin + signatureIdx + 1, signLen - signatureIdx - 1);
					newChild->containedString = newContainedStr;
				}
				newChild->data = data;

				currentNode->next[keyBegin[signatureIdx]&0x000000ff] = newChild;
			}
		}
		else
		{
			currentNode->data = data;
		}
	}
}


void SignatureStorer::add(const char * keyBegin, const char * keyEnd, void * data)
{
	int length = keyEnd - keyBegin;
	//assert(length > 0);
	if (length == 0)
	{
		root.data = data;
	}
	else if (root.next[keyBegin[0]&0x000000ff]==NULL)		//in case of adding a node
	{
		Node* newChild = new Node();
		memSize+=sizeof(Node);
		newChild->father = &root;
		if (length > 1)
		{
			char* newContainedStr = new char[length];
			memSize+=length;
			newContainedStr[0] = (char)(length-1);
			memcpy(newContainedStr + 1, keyBegin+1, length-1);
			newChild->containedString = newContainedStr;
		}
		newChild->data = data;
		(root.next)[keyBegin[0]&0x000000ff] = newChild;
	}
	else												//in case of add in an existing node
	{
		currentNode = (root.next)[keyBegin[0]&0x000000ff];
		AddCurrentNode(keyBegin, keyEnd, 1, data);
	}
}
