#ifndef SIGNATURESTORER_H
#define SIGNATURESTORER_H

#include "node.h"

class SignatureStorer{
private:
	Node root;
	Node* currentNode;
	void AddCurrentNode(const char* keyBegin, const char* keyEnd, int signatureIdx, void* data);
	unsigned int memSize;
public:
	SignatureStorer();
	inline Node* getRoot()
	{
		return &root;
	}
	void add(const char * keyBegin, const char * keyEnd, void * data);
	inline unsigned int size()
	{
		return memSize;
	}
};

	
#endif