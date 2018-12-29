#ifndef _RAGEL_LIB_H_
#define _RAGEL_LIB_H_

#ifndef _RAGEL_DLL_H_
#ifdef RAGELDLL_API
#undef RAGELDLL_API
#endif
#define RAGELDLL_API
#endif

#ifdef WIN32
#pragma comment(lib, "psapi.lib")
#endif

#include <iostream>

using namespace std;

class DFA
{
public:
    class State
    {
    public:
        State()
        {
            isStart = false;
            isEntry = false;
            isFinal = false;
            isDead  = true;
            memset(next, -1, sizeof(next));
            
            data = NULL;
        }
        
        ~State()
        {
        }
        
        bool isStart;
        bool isEntry;
        bool isFinal;
        bool isDead;
        int next[256];
        
        void * data;
    };
    
    DFA()
    {
        stateNum = 0;
        startState = 0;
        state = NULL;
    }
    
    ~DFA()
    {
        if(state != NULL)
        {
            delete []state;
        }
    }
    
    int stateNum;
    int startState;
    State * state;
};

/*
DFA的输入字符为8位无符号整数（256个）；状态编号为32位有符号整数，其中大于或等于0表示有效状态，小于0表示无效状态。
输出参数dfa指向的数据结构在使用完之后需要由用户用delete运算符释放。
返回值大于或等于0表示执行成功，小于0表示执行失败。
*/
RAGELDLL_API int generateDfa(const char * cmd, istream & in, ostream & out, DFA * dfa);

RAGELDLL_API ostream & operator<<(ostream & out, const DFA & dfa);

#endif
