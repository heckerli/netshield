#ifndef _DFA_STRUCT_H_
#define _DFA_STRUCT_H_

#include "NetShield.h"
#include "Global.h"
#include "ragel/ragel-dll.h"

#include <windows.h>
#include <vector>
#include <list>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

using namespace std;

#ifndef verify
#define verify(code) if(!(code)) { fprintf(stderr, "Runtime error: %s:%d\n", __FILE__, __LINE__); exit(0); }
#endif

typedef int (*GenerateDfa)(const char * cmd, istream & in, ostream & out, DFA * dfa);

extern int DFACount;

template <class DFAData>
class DFAStruct
{
public:
    class DFADataWrapper
    {
    public:
        bool hasDollar;
        DFAData data;
        
        DFADataWrapper()
        : hasDollar(false), data()
        {
        }
        
        DFADataWrapper(const DFADataWrapper & wrapper)
        : hasDollar(wrapper.hasDollar), data(wrapper.data)
        {
        }
        
        DFADataWrapper(const bool & hasDollar, const DFAData & data)
        : hasDollar(hasDollar), data(data)
        {
        }
        
        ~DFADataWrapper()
        {
        }
        
        DFADataWrapper & operator=(const DFADataWrapper & wrapper)
        {
            this->hasDollar = wrapper.hasDollar;
            this->data = wrapper.data;
            
            return *this;
        }
    };
    
    DFA dfa;
    
    DFAStruct()
    {
        currentDFAStructTotalSize += size();
    }
    
    ~DFAStruct()
    {
        currentDFAStructTotalSize -= size();
        
        for(INT32_T i = 0; i < dfa.stateNum; i++)
        {
            if(dfa.state[i].data != NULL)
            {
                vector<DFADataWrapper> * vecDFADataWrapper = (vector<DFADataWrapper> *)(dfa.state[i].data);
                delete vecDFADataWrapper;
                dfa.state[i].data = NULL;
            }
        }
    }
    
    UINT32_T size()
    {
        UINT32_T result = 0;
        
        result += sizeof(DFAStruct);
        result += sizeof(DFA::State) * dfa.stateNum;
        
        for(int i = 0; i < dfa.stateNum; i++)
        {
            if(dfa.state[i].isFinal == true && dfa.state[i].data != NULL)
            {
                vector<DFADataWrapper> * vecDFADataWrapper = (vector<DFADataWrapper> *)(dfa.state[i].data);
                result += vecDFADataWrapper->size() * sizeof(DFADataWrapper);
            }
        }
        
        return result;
    }
    
    // 根据regex编译DFA
    INT32_T compile(string regex)
    {
        currentDFAStructTotalSize -= size();
        
        if(dfa.state != NULL)
        {
            delete [](dfa.state);
            dfa.state = NULL;
            
            dfa.stateNum = 0;
            dfa.startState = 0;
        }
        
        // cout << DFACount << ": " << regex << "\n";
        removeDollar(regex);
		// cout << "After '$' removed: " << regex << "\n";
        
        stringstream in;
        in << "%%{"
	          "machine DFAStruct" << DFACount << ";"
	          "main" << DFACount << ":= "
	          << regex << ";"
              "}%%";
        
		DFACount++;
		
		HINSTANCE hDll; 
        GenerateDfa pGenerateDfa; 
        int fFreeResult = 0; 
     
        // Get a handle to the DLL module.
     
        hDll = LoadLibrary(TEXT("ragel-dll.dll")); 
     
        // If the handle is valid, try to get the function address.
     
        if (hDll == NULL) 
        {
            fprintf(stderr, "Cannot load ragel-dll.dll!\n");
            exit(0);
        }
        
        pGenerateDfa = (GenerateDfa)GetProcAddress(hDll, "generateDfa"); 
     
        // If the function address is valid, call the function.
     
        if(pGenerateDfa == NULL) 
        {
            fprintf(stderr, "Cannot find function generateDfa() in ragel-dll.dll!\n");
            exit(0);
        }

        (pGenerateDfa)("-t -n", in, cout, &dfa);
        
        // Free the DLL module.
        fFreeResult = FreeLibrary(hDll);
        
        if(fFreeResult == 0)
        {
            fprintf(stderr, "Cannot unload ragel-dll.dll!\n");
        }
        
        currentDFAStructTotalSize += size();

        return 0;
    }
    
    // 为每一个final state标注信息
    INT32_T annotate(const DFAData & data, bool hasDollar)
    {
        currentDFAStructTotalSize -= size();
        
        for(INT32_T i = 0; i < dfa.stateNum; i++)
        {
            if(dfa.state[i].isFinal == true)
            {
                vector<DFADataWrapper> * vecDFADataWrapper = NULL;
                if(dfa.state[i].data == NULL)
                {
                    vecDFADataWrapper = new vector<DFADataWrapper>;
                    verify(vecDFADataWrapper);
                    dfa.state[i].data = vecDFADataWrapper;
                }
                else
                {
                    vecDFADataWrapper = (vector<DFADataWrapper> *)(dfa.state[i].data);
                }
                
                vecDFADataWrapper->push_back(DFADataWrapper(hasDollar, data));
            }
        }
        
        currentDFAStructTotalSize += size();

		return 0;
    }
    
    // 根据子DFA的状态信息标注本DFA的状态信息
    INT32_T annotate(const DFAStruct & subDfa)
    {
        currentDFAStructTotalSize -= size();
        
        for(INT32_T i = 0; i < dfa.stateNum; i++)
        {
            if(dfa.state[i].isFinal == true)
            {
                INT32_T current = i;
                list<INT32_T> state;
                list<UINT8_T> ch;
                
                state.push_front(current);
                while(dfa.state[current].isStart == false)
                {
                    bool hasPredecessor = false;
                    for(INT32_T j = 0; j < dfa.stateNum; j++)
                    {
                        for(UINT32_T k = 0; k < 256; k++)
                        {
                            if(dfa.state[j].next[k] == current && find(state.begin(), state.end(), j) == state.end())
                            {
                                state.push_front(j);
                                ch.push_front((UINT8_T)k);
                                current = j;
                                
                                hasPredecessor = true;
                                goto find_predecessor;
                            }
                        }
                    }
                    
                    find_predecessor:
                    if(hasPredecessor == false)
                    {
                        fprintf(stderr, "Cannot find predecessor!\n");
                        exit(0);
                    }
                }
                
                list<UINT8_T>::const_iterator chIt = ch.begin();
                current = subDfa.dfa.startState;
                while(chIt != ch.end() && current >= 0)
                {
                    current = subDfa.dfa.state[current].next[*chIt];
                    chIt++;
                }
                
                if(current >= 0 && subDfa.dfa.state[current].isFinal == true)
                {
                    vector<DFADataWrapper> * vecDfaDFAData = NULL;
                    if(dfa.state[i].data == NULL)
                    {
                        vecDfaDFAData = new vector<DFADataWrapper>;
                        verify(vecDfaDFAData);
                        dfa.state[i].data = vecDfaDFAData;
                    }
                    else
                    {
                        vecDfaDFAData = (vector<DFADataWrapper> *)(dfa.state[i].data);
                    }
                    
                    vector<DFADataWrapper> * vecSubDfaDFAData = (vector<DFADataWrapper> *)(subDfa.dfa.state[current].data);
                    vecDfaDFAData->insert(vecDfaDFAData->end(), vecSubDfaDFAData->begin(), vecSubDfaDFAData->end());
                }
            }
        }
        
        currentDFAStructTotalSize += size();

		return 0;
    }
};

template <class DFAData>
ostream & operator<<(ostream & out, const DFAStruct<DFAData> & dfa)
{
    for(int i = 0; i < dfa.dfa.stateNum; i++)
    {
        if(dfa.dfa.state[i].isStart == true)
        {
            out << "state " << i << ": [start]\n";
        }
        else if(dfa.dfa.state[i].isEntry == true)
        {
            out << "state " << i << ": [entry]\n";
        }
    }
    out << "\n";
    
    for(int i = 0; i < dfa.dfa.stateNum; i++)
    {
        out << "state " << i << ":";
        if(dfa.dfa.state[i].isStart == true)
        {
            out << " [start]";
        }
        else if(dfa.dfa.state[i].isEntry == true)
        {
            out << " [entry]";
        }
        
        if(dfa.dfa.state[i].isDead == true)
        {
            out << " [dead]";
        }
        
        if(dfa.dfa.state[i].isFinal == true)
        {
            out << " [final]";
            if(dfa.dfa.state[i].data != NULL)
            {
				vector<DFAStruct<DFAData>::DFADataWrapper> * vecFinalData = (vector<DFAStruct<DFAData>::DFADataWrapper> *)(dfa.dfa.state[i].data);
                vector<DFAStruct<DFAData>::DFADataWrapper>::const_iterator it = vecFinalData->begin();
                
                out << " ->";
                while(it != vecFinalData->end())
                {
                    out << " " << (*it).data;
                    if((*it).hasDollar == true)
                    {
                        out << "$";
                    }
                    
                    it++;
                }
            }
        }
        out << "\n";
        
        for(int j = 0; j < 256; j++)
        {
            if(dfa.dfa.state[i].next[j] >= 0)
            {
                if(j == '\n')
                {
                    out << "'\\n'";
                }
                else if(j == '\t')
                {
                    out << "'\\t'";
                }
                else if(j == '\v')
                {
                    out << "'\\v'";
                }
                else if(j == '\b')
                {
                    out << "'\\b'";
                }
				else if(j == '\r')
                {
                    out << "'\\r'";
                }
				else if(j == '\f')
                {
                    out << "'\\f'";
                }
				else if(j == '\a')
                {
                    out << "'\\a'";
                }
                else if(32 <= j && j < 127)
                {
                    out << "'" << (char)j << "'";
                }
                else
                {
                    out << j;
                }
                
                out << " into state " << dfa.dfa.state[i].next[j] << "\n";
            }
        }
        out << "\n";
    }
    
    return out;
}

#endif
