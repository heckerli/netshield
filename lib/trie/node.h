#ifndef NODE_H
#define NODE_H

#include <stddef.h>

typedef struct node{
	char* containedString;
	struct node* father;
	struct node* next[256];
	void* data;

	node()
	{
		containedString = NULL;
		father = NULL;
		for (int i = 0; i<256 ; i++)
			next[i] = NULL;
		data = NULL;
	}

	~node()
	{
		if (containedString!=NULL)
			delete[] containedString;
		for (int i = 0; i<256 ; i++)
		{
			if (next[i]!=NULL)
				delete next[i];
		}
	}
} Node;

#endif