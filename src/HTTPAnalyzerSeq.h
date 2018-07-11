#ifndef _HTTP_ANALYZER_SEQ_H_
#define _HTTP_ANALYZER_SEQ_H_

#include "NetShield.h"
#include "Util.h"
#include "TrieStruct.h"
#include "TrieMatcher.h"
#include "DFAStruct.h"
#include "DFAMatcher.h"

#include <vector>

using namespace std;

class StringMatcher
{
public:
    StringMatcher(const char * pattern)
    {
        this->pattern = new char[strlen(pattern) + 1];
        strcpy(this->pattern, pattern);
    }
    
    ~StringMatcher()
    {
    }
    
    bool match(const Field & field)
    {
        if(field.parsingState != FINISHED)
        {
            return false;
        }
        
        if(field.dataBegin == NULL || field.dataEnd == NULL)
        {
            return false;
        }
        
        return strncmp((const char *)(field.dataBegin), pattern, ((int)strlen(pattern) > (field.dataEnd - field.dataBegin)) ? 
                        strlen(pattern) : (field.dataEnd - field.dataBegin)) == 0;
    }

protected:
    char * pattern;
};

class RegexMatcher
{
public:
    RegexMatcher(const char * regex)
    {
        dfa.compile(regex);
        dfa.annotate(true, hasDollar(regex));
        matcher.init(&dfa);
        
        matched = false;
    }
    
    ~RegexMatcher()
    {
    }
    
    bool match(const Field & field)
    {
        if(field.parsingState != FINISHED)
        {
            return false;
        }
        
        if(field.dataBegin == NULL || field.dataEnd == NULL)
        {
            return false;
        }
        
        matcher.match((const UINT8_T *)(field.dataBegin), (const UINT8_T *)(field.dataEnd), matchedCallback, this);
        matcher.getCurrentState(matchedCallback, this);
        
        BOOL_T matchedCurrent = matched;
        matched = false;
        matcher.reset();
        
        return matchedCurrent;
    }

protected:
    DFAStruct<BOOL_T> dfa;
    DFAMatcher<BOOL_T> matcher;
    BOOL_T matched;
    
    static void matchedCallback(const BOOL_T & b, void * cbParam)
    {
        RegexMatcher * regexMatcher = (RegexMatcher *)cbParam;
        
        regexMatcher->matched = true;
    }
};

class LengthMatcher
{
public:
    LengthMatcher(int length)
    {
        this->length = length;
    }
    
    ~LengthMatcher()
    {
    }
    
    bool match(const Field & field)
    {
        if(field.parsingState != FINISHED)
        {
            return false;
        }
        
        if(field.dataBegin == NULL || field.dataEnd == NULL)
        {
            return false;
        }
        
        return (field.dataEnd - field.dataBegin) > length;
    }
    
protected:
    int length;
};

class AnyElementStringMatcher
{
public:
    AnyElementStringMatcher(const char * pattern)
    : stringMatcher(pattern)
    {
    }
    
    ~AnyElementStringMatcher()
    {
    }
    
    bool match(const vector<Field> & vec)
    {
        vector<Field>::const_iterator it = vec.begin();
        while(it != vec.end())
        {
            if(stringMatcher.match(*it) == true)
            {
                return true;
            }
            it++;
        }
        
        return false;
    }

protected:
    StringMatcher stringMatcher;
};

class AnyElementLengthMatcher
{
public:
    AnyElementLengthMatcher(int length)
    : lengthMatcher(length)
    {
    }
    
    ~AnyElementLengthMatcher()
    {
    }
    
    bool match(const vector<Field> & vec)
    {
        vector<Field>::const_iterator it = vec.begin();
        while(it != vec.end())
        {
            if(lengthMatcher.match(*it) == true)
            {
                return true;
            }
            it++;
        }
        
        return false;
    }

protected:
    LengthMatcher lengthMatcher;
};

class ElementStringMatcher
{
public:
    ElementStringMatcher(int index, const char * pattern)
    : stringMatcher(pattern)
    {
        this->index = index;
    }
    
    ~ElementStringMatcher()
    {
    }
    
    bool match(const vector<Field> & vec)
    {
        if(index > 0)
        {
            index = - index;
        }
        
        int idx = vec.size() - 1 - index;
        if(idx >= 0 && idx < (int)(vec.size()))
        {
            return stringMatcher.match(vec[idx]);
        }
        
        return false;
    }
    
protected:
    StringMatcher stringMatcher;
    int index;
};

class FieldPairStringMatcher
{
public:
    FieldPairStringMatcher(const char * keyPattern, const char * valuePattern)
    : keyMatcher(keyPattern), valueMatcher(valuePattern)
    {
    }
    
    ~FieldPairStringMatcher()
    {
    }
    
    bool match(const vector<Field> & keyVector, const vector<Field> & valueVector)
    {
        for(unsigned int i = 0; i < keyVector.size(); i++)
        {
            if(keyMatcher.match(keyVector[i]) == false)
            {
                continue;
            }
            
            if(valueMatcher.match(valueVector[i]) == true)
            {
                return true;
            }
        }
        
        return false;
    }
    
protected:
    StringMatcher keyMatcher;
    StringMatcher valueMatcher;
};

class FieldPairRegexMatcher
{
public:
    FieldPairRegexMatcher(const char * keyPattern, const char * valueRegex)
    : keyMatcher(keyPattern), valueMatcher(valueRegex)
    {
    }
    
    ~FieldPairRegexMatcher()
    {
    }
    
    bool match(const vector<Field> & keyVector, const vector<Field> & valueVector)
    {
        for(unsigned int i = 0; i < keyVector.size(); i++)
        {
            if(keyMatcher.match(keyVector[i]) == false)
            {
                continue;
            }
            
            if(valueMatcher.match(valueVector[i]) == true)
            {
                return true;
            }
        }
        
        return false;
    }
    
protected:
    StringMatcher keyMatcher;
    RegexMatcher valueMatcher;
};

class FieldPairLengthMatcher
{
public:
    FieldPairLengthMatcher(const char * keyPattern, int valueLength)
    : keyMatcher(keyPattern), valueMatcher(valueLength)
    {
    }
    
    ~FieldPairLengthMatcher()
    {
    }
    
    bool match(const vector<Field> & keyVector, const vector<Field> & valueVector)
    {
        for(unsigned int i = 0; i < keyVector.size(); i++)
        {
            if(keyMatcher.match(keyVector[i]) == false)
            {
                continue;
            }
            
            if(valueMatcher.match(valueVector[i]) == true)
            {
                return true;
            }
        }
        
        return false;
    }
    
protected:
    StringMatcher keyMatcher;
    LengthMatcher valueMatcher;
};

void HTTPAnalyzerSeqInit();

void HTTPAnalyzerSeqMatch(const Field & methodField, const Field & filenameField,
                          const vector<Field> & dirFieldVector, const vector<Field> & varNameVector, 
                          const vector<Field> & varValueVector, const vector<Field> & headerNameVector,
                          const vector<Field> & headerValueVector, const Field & assignmentField, const Field & uriField);

#endif
