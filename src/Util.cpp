#include "NetShield.h"
#include "Util.h"
#include "Global.h"
#include "Connection.h"

#if defined(WIN32) || defined(WIN64)
#include <sys/timeb.h>
#include <winsock2.h>
#endif

#include <string>
#include <vector>

using namespace std;

void DebugMessage(const INT8_T * format, ...)
{
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}

/*
INT32_T strncmpi(const INT8_T *s1, const INT8_T *s2, UINT32_T n)
{
    for(UINT32_T i = 0; i < n; i++)
    {
        INT8_T c1 = tolower(s1[i]);
        INT8_T c2 = tolower(s2[i]);
        
        if(c1 != c2)
        {
            return c1 - c2;
        }
    }
    
    return 0;
}
*/

INT8_T ReportError(Connection * conn, const INT8_T * format, /*args*/ ...)
{
    if(silent->count == 0)
    {
        if(reassembled->count > 0)
        {
            printf("Connection %u, ", conn->tuple5.origIP);
        }
        else
        {
            printf("Connection %s, ", conn->tuple5.toString().c_str());
        }
        
        va_list ap;
        va_start(ap, format);
        vprintf(format, ap);
        va_end(ap);
    
    	printf("\n");
    }
    
    if(filterError->count > 0 && reassembled->count == 0)
    {
        Tuple5 tuple5 = conn->tuple5;
        Tuple5::sort(&tuple5);
        
        if(filterTuple5Map.find(tuple5) != filterTuple5Map.end())
        {
            filterTuple5Map[tuple5] = false;
        }
    }
    
    return 0;
}

std::ostream & operator<<(std::ostream & out, const Rule & rule)
{
    out << "(" << rule.columnID << ", " << rule.ruleID << ")";
    return out;
}

INT32_T loadStringStruct(TrieStruct<Rule> * trie, TiXmlHandle & hString)
{
    TiXmlElement * pExpression = hString.FirstChild("Expression").ToElement();
    while(pExpression != NULL)
    {
        const char * exp = pExpression->Attribute("Exp");
        verify(exp);
        
        TiXmlElement * pRule = pExpression->FirstChildElement("Rule");
        while(pRule != NULL)
        {
            INT32_T ColumnID, RuleID;
            if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
            {
                fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
            }
            
            if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
            {
                fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
            }
            
            // subDFA->annotate(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
            trie->add(exp, Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
            
            pRule = pRule->NextSiblingElement("Rule");
        }
                
        pExpression = pExpression->NextSiblingElement("Expression");
    }
    
    return 0;
}

INT32_T loadDFAStruct(DFAStruct<Rule> * dfa, TiXmlHandle & hRegex)
{
    string combinedRegex;
    vector<DFAStruct<Rule> *> subDFAVector;
    TiXmlElement * pExpression = hRegex.FirstChild("Expression").ToElement();
    while(pExpression != NULL)
    {
        if(combinedRegex.length() != 0)
        {
            combinedRegex += "|";
        }
        const char * exp = pExpression->Attribute("Exp");
        verify(exp);
        combinedRegex += exp;
        
        DFAStruct<Rule> * subDFA = new DFAStruct<Rule>;
        subDFA->compile(exp);
        
        TiXmlElement * pRule = pExpression->FirstChildElement("Rule");
        while(pRule != NULL)
        {
            INT32_T ColumnID, RuleID;
            if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
            {
                fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
            }
            
            if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
            {
                fprintf(stderr, "Error on reading \"Rule RuleID\"!\n");
            }
            
            subDFA->annotate(Rule((UINT16_T)ColumnID, (UINT16_T)RuleID), hasDollar(exp));
            
            pRule = pRule->NextSiblingElement("Rule");
        }
        
        subDFAVector.push_back(subDFA);
        
        pExpression = pExpression->NextSiblingElement("Expression");
    }
    
    if(combinedRegex.length() > 0)
    {
        dfa->compile(combinedRegex.c_str());
        vector<DFAStruct<Rule> *>::iterator it = subDFAVector.begin();
        while(it != subDFAVector.end())
        {
            dfa->annotate(**it);
            delete *it;
            it++;
        }
    }
    
    return 0;
}

INT32_T loadLengthStruct(IntRangeStruct<Rule> * intRangeStruct, TiXmlHandle & hLength)
{
    TiXmlElement * pExpression = hLength.FirstChild("Expression").ToElement();
    while(pExpression != NULL)
    {
        INT32_T key = 0;
        if(pExpression->QueryIntAttribute("Exp", &key) != TIXML_SUCCESS)
        {
            fprintf(stderr, "Error on reading attribute \"Expression Exp\"!\n");
        }
        
        TiXmlElement * pRule = pExpression->FirstChildElement("Rule");
        while(pRule != NULL)
        {
            INT32_T ColumnID, RuleID;
            if(pRule->QueryIntAttribute("ColumnID", &ColumnID) != TIXML_SUCCESS)
            {
                fprintf(stderr, "Error on reading attribute \"Rule ColumnID\"!\n");
            }
            
            if(pRule->QueryIntAttribute("RuleID", &RuleID) != TIXML_SUCCESS)
            {
                fprintf(stderr, "Error on reading attribute \"Rule RuleID\"!\n");
            }
            
            intRangeStruct->add(key, Rule((UINT16_T)ColumnID, (UINT16_T)RuleID));
            
            pRule = pRule->NextSiblingElement("Rule");
        }
        
        pExpression = pExpression->NextSiblingElement("Expression");
    }
    
    return 0;
}

INT32_T printField(const Field & field, FILE * fp)
{
    fprintf(fp, "parsingState = ");
    switch(field.parsingState)
    {
    case INVALID:
        fprintf(fp, "INVALID");
        break;
    case INPROCESS:
        fprintf(fp, "INPROCESS");
        break;
    case FINISHED:
        fprintf(fp, "FINISHED");
        break;
    default:
        break;
    }
    fprintf(fp, "\n");
    
    bool noMatched = true;
    fprintf(fp, "matchingState = ");
    if((field.matchingState & STRING_MATCHED) != 0)
    {
        fprintf(fp, "STRING_MATCHED");
        noMatched = false;
    }
    
    if((field.matchingState & REGEX_MATCHED) != 0)
    {
        if(noMatched == false)
        {
            fprintf(fp, " | ");
        }
        
        fprintf(fp, "REGEX_MATCHED");
        noMatched = false;
    }
    
    if((field.matchingState & LENGTH_MATCHED) != 0)
    {
        if(noMatched == false)
        {
            fprintf(fp, " | ");
        }
        
        fprintf(fp, "LENGTH_MATCHED");
        noMatched = false;
    }
    
    if(noMatched == true)
    {
        fprintf(fp, "NEVER_MATCHED");
    }
    
    fprintf(fp, "\n");
    
    fprintf(fp, field.isPermanent == false ? "isPermanent = false\n" : "isPermanent = true\n");
    
    if(field.parsingState != INVALID)
    {
        fprintf(fp, "data = \"");
        fwrite(field.dataBegin, sizeof(UINT8_T), field.dataEnd - field.dataBegin, fp);
        fprintf(fp, "\"");
    }
    
    return 0;
}

// check if regex has tail qualifier '$'
bool hasDollar(const string & regex)
{
    if(regex.length() == 0)
    {
        return false;
    }
    
    int lastValidCharPos = regex.length() - 1;
    if(regex[0] == '/')
    {
        while(lastValidCharPos >= 0)
        {
            if(regex[lastValidCharPos] == '/')
            {
                lastValidCharPos--;
                if(lastValidCharPos <= 0)
                {
                    return false;
                }
                else
                {
                    break;
                }
            }
			else
			{
				break;
			}
        }
    }
    
    if(regex[lastValidCharPos] != '$')
    {
        return false;
    }
    
    int i = lastValidCharPos - 1;
    int backslachNum = 0;
    while(i >= 0)
    {
        if(regex[i] != '\\')
        {
            break;
        }
        
        backslachNum++;
        i--;
    }
    
    // has valid qualifier '$'
    if(backslachNum % 2 == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void removeDollar(string & regex)
{
    int dollarPos = regex.find('$', 0);
    while(dollarPos < regex.length())
    {
        int i = dollarPos - 1;
        int backslachNum = 0;
        while(i >= 0)
        {
            if(regex[i] != '\\')
            {
                break;
            }
            
            backslachNum++;
            i--;
        }
        
        // has valid qualifier '$'
        if(backslachNum % 2 == 0)
        {
            regex = regex.erase(dollarPos, 1);
        }
        else
        {
            dollarPos++;
        }
        
        if(dollarPos < regex.length())
        {
            dollarPos = regex.find('$', dollarPos);
        }
    }
}

#if defined(WIN32) || defined(WIN64)
int ns_gettimeofday(struct timeval *tv, struct timezone *tz) {
    struct _timeb tb;

	if(tv==NULL) return -1;
	_ftime(&tb);
	tv->tv_sec = tb.time;
	tv->tv_usec = ((int) tb.millitm) * 1000;
	return 0;
}
#endif
