#ifndef _HTTP_ANALYZER_H_
#define _HTTP_ANALYZER_H_

#include <vector>
#include <map>

#include "NetShield.h"
#include "FlowAnalyzer.h"
#include "Runnable.h"
#include "DFAStruct.h"
#include "DFAMatcher.h"
#include "IntRangeStruct.h"
#include "IntRangeMatcher.h"
#include "TrieStruct.h"
#include "TrieMatcher.h"
#include "CSAlgo.h"
#include "HTTPAnalyzerSeq.h"
#include "http_pac_fast.h"
#include "Vector.h"

using namespace binpac;

// (x & 0x80)是为了处理大于128的字符
#define INSET(B, x) ((x & 0x80) || ((B)[(x) >> 3] & 1 << ((x) & 0x07)))

template <class MatchingStruct>
class ArrayMatchingStruct
{
public:
    int index;
    MatchingStruct matchingStruct;
    
    ArrayMatchingStruct()
    : index(0), matchingStruct()
    {
    }
    
    ArrayMatchingStruct(int index, MatchingStruct matchingStruct)
    : index(index), matchingStruct(matchingStruct)
    {
    }
    
    ArrayMatchingStruct(const ArrayMatchingStruct & x)
    : index(x.index), matchingStruct(x.matchingStruct)
    {
    }
    
    ArrayMatchingStruct & operator=(const ArrayMatchingStruct & x)
    {
        this->index = x.index;
        this->matchingStruct = x.matchingStruct;
        
        return *this;
    }
    
    ~ArrayMatchingStruct()
    {
    }
};

class DictKeyData
{
public:
    int stringGroup;
    int regexGroup;
    int lengthGroup;
    vector<vector<Rule> *> stringRuleVector;
    vector<vector<Rule> *> regexRuleVector;
    vector<vector<Rule> *> lengthRuleVector;
    
    DictKeyData()
    {
        stringGroup = -1;
        regexGroup = -1;
        lengthGroup = -1;
    }
};

#define NEW_MATCHER(_type_, _matcher_, _struct_) if((_struct_) != NULL) \
    { \
        (_matcher_) = new _type_(_struct_); \
        verify(_matcher_); \
    } \
    else \
    { \
        (_matcher_) = NULL; \
    }

#define RESET_MATCHER(_matcher_) if(_matcher_) { (_matcher_)->reset(); }

class HTTPAnalyzer : public FlowAnalyzer
{
public:
    HTTPAnalyzer(FlowHandler * flow, FlowDir dir, bool isPac)
    : FlowAnalyzer(flow, dir)
    {
        // DEBUG_WRAP(DebugMessage("HTTPAnalyzer::HTTPAnalyzer()\n"););
        init();
        
        this->isPac = isPac;
        parser = NULL;
        
        dirFieldVector.reserve(8);
        
        NEW_MATCHER(TrieMatcher<Rule>, methodStringMatcher, methodStringStruct);
        // NEW_MATCHER(DFAMatcher<Rule>, methodDFAMatcher, methodDFAStruct);
        NEW_MATCHER(IntRangeMatcher<Rule>, methodLengthMatcher, methodLengthStruct);
        
        NEW_MATCHER(TrieMatcher<Rule>, filenameStringMatcher, filenameStringStruct);
        NEW_MATCHER(DFAMatcher<Rule>, filenameDFAMatcher, filenameDFAStruct);
        NEW_MATCHER(IntRangeMatcher<Rule>, filenameLengthMatcher, filenameLengthStruct);
        
        NEW_MATCHER(TrieMatcher<Rule>, anydirStringMatcher, anydirStringStruct);
        NEW_MATCHER(DFAMatcher<Rule>, anydirDFAMatcher, anydirDFAStruct);
        NEW_MATCHER(IntRangeMatcher<Rule>, anydirLengthMatcher, anydirLengthStruct);
        
        vector< ArrayMatchingStruct<TrieStruct<Rule> *> >::const_iterator dirStringStructVectorIt = dirStringStructVector.begin();
        while(dirStringStructVectorIt != dirStringStructVector.end())
        {
            TrieMatcher<Rule> * dirStringMatcher = NULL;
            NEW_MATCHER(TrieMatcher<Rule>, dirStringMatcher, (*dirStringStructVectorIt).matchingStruct);
            dirStringMatcherVector.push_back(dirStringMatcher);
            
            dirStringStructVectorIt++;
        }
        
        NEW_MATCHER(TrieMatcher<DictKeyData *>, headernameStringMatcher, headernameStringStruct);
        headerStringGroupMatcher = new TrieMatcher<UINT32_T>;
        verify(headerStringGroupMatcher);
        headerRegexGroupMatcher = new DFAMatcher<UINT32_T>;
        verify(headerRegexGroupMatcher);
        headerLengthGroupMatcher = new IntRangeMatcher<UINT32_T>;
        verify(headerLengthGroupMatcher);
        headerDictKeyData = NULL;
        
        NEW_MATCHER(TrieMatcher<DictKeyData *>, varnameStringMatcher, varnameStringStruct);
        varStringGroupMatcher = new TrieMatcher<UINT32_T>;
        verify(varStringGroupMatcher);
        varRegexGroupMatcher = new DFAMatcher<UINT32_T>;
        verify(varRegexGroupMatcher);
        varLengthGroupMatcher = new IntRangeMatcher<UINT32_T>;
        verify(varLengthGroupMatcher);
        varDictKeyData = NULL;
        
        NEW_MATCHER(TrieMatcher<Rule>, assignmentStringMatcher, assignmentStringStruct);
        NEW_MATCHER(DFAMatcher<Rule>, assignmentDFAMatcher, assignmentDFAStruct);
        NEW_MATCHER(IntRangeMatcher<Rule>, assignmentLengthMatcher, assignmentLengthStruct);
        
        NEW_MATCHER(TrieMatcher<Rule>, uriStringMatcher, uriStringStruct);
        NEW_MATCHER(DFAMatcher<Rule>, uriDFAMatcher, uriDFAStruct);
        NEW_MATCHER(IntRangeMatcher<Rule>, uriLengthMatcher, uriLengthStruct);
        
        csalgoColumnMatchedRuleVector.reserve(HTTPAnalyzer::columnNum);
        for(UINT32_T i = 0; i < HTTPAnalyzer::columnNum; i++)
        {
            vector<UINT16_T> * vec = new vector<UINT16_T>;
            verify(vec);
            vec->reserve(8);
            csalgoColumnMatchedRuleVector.push_back(vec);
        }
        
        if(parseOnly->count == 0 && seqMatch->count == 0)
        {
            csalgo.init(HTTPAnalyzer::ruleMatrix, HTTPAnalyzer::ruleGrpSID, HTTPAnalyzer::columnNum, HTTPAnalyzer::ruleNum);
        }
        
        resetState();
        
        if(instanceNum == 0 && writeLog->count > 0)
        {
            logFile = fopen("HTTP.log", "wb");
            verify(logFile != NULL);
        }
        
        instanceNum++;
    }
    
    virtual ~HTTPAnalyzer()
    {
        // DEBUG_WRAP(DebugMessage("HTTPAnalyzer::~HTTPAnalyzer()\n"););

        instanceNum--;
        if(instanceNum == 0 && logFile != NULL)
        {
            fclose(logFile);
            logFile = NULL;
        }
        
        vector<vector<UINT16_T> *>::iterator csalgoColumnMatchedRuleVectorIt = csalgoColumnMatchedRuleVector.begin();
        while(csalgoColumnMatchedRuleVectorIt != csalgoColumnMatchedRuleVector.end())
        {
            if(*csalgoColumnMatchedRuleVectorIt != NULL)
            {
                delete *csalgoColumnMatchedRuleVectorIt;
            }
            
            csalgoColumnMatchedRuleVectorIt++;
        }
        
        /*
        if(parser != NULL)
        {
            delete parser;
        }
        */
    }
    
    static INT32_T init();

	INT32_T resetState()
    {
        if(parseOnly->count == 0 || logFile != NULL)
        {
            methodField.reset();
            filenameField.reset();
            varName.reset();
            varValue.reset();
            dirField.reset();
            dirFieldVector.clear();
            dirString.clear();
            assignmentField.reset();
            uriField.reset();
            
            parseHttpHeaderNameField.reset();
            parseHttpHeaderValueField.reset();
            
            RESET_MATCHER(methodStringMatcher);
            // RESET_MATCHER(methodDFAMatcher);
            RESET_MATCHER(methodLengthMatcher);
            
            RESET_MATCHER(filenameStringMatcher);
            RESET_MATCHER(filenameDFAMatcher);
            RESET_MATCHER(filenameLengthMatcher);
            
            RESET_MATCHER(anydirStringMatcher);
            RESET_MATCHER(anydirDFAMatcher);
            RESET_MATCHER(anydirLengthMatcher);
            
            vector<TrieMatcher<Rule> *>::iterator dirStringMatcherVectorIt = dirStringMatcherVector.begin();
            while(dirStringMatcherVectorIt != dirStringMatcherVector.end())
            {
                RESET_MATCHER((*dirStringMatcherVectorIt));
                
                dirStringMatcherVectorIt++;
            }
            
            RESET_MATCHER(headernameStringMatcher);
            RESET_MATCHER(headerStringGroupMatcher);
            RESET_MATCHER(headerRegexGroupMatcher);
            RESET_MATCHER(headerLengthGroupMatcher);
            headerDictKeyData = NULL;
            
            RESET_MATCHER(varnameStringMatcher);
            RESET_MATCHER(varStringGroupMatcher);
            RESET_MATCHER(varRegexGroupMatcher);
            RESET_MATCHER(varLengthGroupMatcher);
            varDictKeyData = NULL;
            
            RESET_MATCHER(assignmentStringMatcher);
            RESET_MATCHER(assignmentDFAMatcher);
            RESET_MATCHER(assignmentLengthMatcher);
            
            RESET_MATCHER(uriStringMatcher);
            RESET_MATCHER(uriDFAMatcher);
            RESET_MATCHER(uriLengthMatcher);
            
            vector<vector<UINT16_T> *>::iterator csalgoColumnMatchedRuleVectorIt = csalgoColumnMatchedRuleVector.begin();
            while(csalgoColumnMatchedRuleVectorIt != csalgoColumnMatchedRuleVector.end())
            {
                (*csalgoColumnMatchedRuleVectorIt)->clear();
                
                csalgoColumnMatchedRuleVectorIt++;
            }
            
            varNameVector.clear();
            varValueVector.clear();
            
            headerNameVector.clear();
            headerValueVector.clear();
            
            csalgo.reset();
        }
                
        return 0;
    }
    
    virtual INT32_T reset(FlowHandler * flow, FlowDir dir)
    {
        FlowAnalyzer::reset(flow, dir);
        
        resetState();
        
        if(parser != NULL)
        {
            parser->Reset();
        }
        
        return 0;
    }
    
    virtual INT32_T run();

// protected:
    enum ExpectBody
    {
        BODY_EXPECTED,
        BODY_NOT_EXPECTED,
        BODY_MAYBE,
    };
    
    enum DeliveryMode
    {
        UNKNOWN_DELIVERY_MODE,
        CONTENT_LENGTH,
        CHUNKED,
        MULTIPART,
    };
    
    enum UirParsingState
    {
        ABS_PATH,
        DIRECTORY,
        EXPECT_QUERY,
        EXPECT_FRAGMENT,
        VAR_NAME,
        VAR_VALUE,
        FINISH,
        BAD,
    };
    
    static const UINT8_T PROTO_CHAR[128];
    static const UINT8_T HOST_CHAR[128];
    static const UINT8_T DIR_CHAR[128];
    static const UINT8_T VAR_CHAR[128];
    static const UINT8_T VALUE_CHAR[128];
    static const UINT8_T FRAGMENT_CHAR[128];
    
    static UINT8_T PROTO[16];
    static UINT8_T HOST[16];
    static UINT8_T DIR[16];
    static UINT8_T VAR[16];
    static UINT8_T VALUE[16];
    static UINT8_T FRAGMENT[16];
    
    static UINT8_T * ruleMatrix;
    static UINT32_T * ruleGrpSID;
    static UINT32_T ruleNum;
    static UINT32_T columnNum;
    
    static TrieStruct<Rule> * methodStringStruct;
    static DFAStruct<Rule> * methodDFAStruct;
    static IntRangeStruct<Rule> * methodLengthStruct;
    
    static TrieStruct<Rule> * filenameStringStruct;
    static DFAStruct<Rule> * filenameDFAStruct;
    static IntRangeStruct<Rule> * filenameLengthStruct;
    
    static TrieStruct<Rule> * anydirStringStruct;
    static DFAStruct<Rule> * anydirDFAStruct;
    static IntRangeStruct<Rule> * anydirLengthStruct;
    
    static vector< ArrayMatchingStruct<TrieStruct<Rule> *> > dirStringStructVector;
    
    static TrieStruct<DictKeyData *> * varnameStringStruct;
    static vector<TrieStruct<UINT32_T> *> * varStringGroupStructVector;
    static vector<DFAStruct<UINT32_T> *> * varRegexGroupStructVector;
    static vector<IntRangeStruct<UINT32_T> *> * varLengthGroupStructVector;
    
    static TrieStruct<Rule> * assignmentStringStruct;
    static DFAStruct<Rule> * assignmentDFAStruct;
    static IntRangeStruct<Rule> * assignmentLengthStruct;
    
    static TrieStruct<Rule> * uriStringStruct;
    static DFAStruct<Rule> * uriDFAStruct;
    static IntRangeStruct<Rule> * uriLengthStruct;
    
    static TrieStruct<DictKeyData *> * headernameStringStruct;
    static vector<TrieStruct<UINT32_T> *> * headerStringGroupStructVector;
    static vector<DFAStruct<UINT32_T> *> * headerRegexGroupStructVector;
    static vector<IntRangeStruct<UINT32_T> *> * headerLengthGroupStructVector;
    
    static BOOL_T isInitialized;
    static INT32_T initBitmap(UINT8_T * bitmap, const UINT8_T charSet[]);
    static INT32_T loadConfig(TiXmlDocument & config);
    static INT32_T loadRulesConfig(TiXmlHandle & hRules);
    static INT32_T loadVariablesConfig(TiXmlHandle & hVariableDict);
    static INT32_T loadHeadersConfig(TiXmlHandle & hHeaderDict);
    
    static UINT32_T instanceNum;
    static FILE * logFile;
    
    bool isPac;
    FastParser * parser;
    
    INT32_T contentLength;
    DeliveryMode deliveryMode;
    
    UINT8_T headerName[20];
    UINT8_T headerValue[20];
    
    Field methodField;
    Field filenameField;
    vector<Field> dirFieldVector;
    Field assignmentField;
    Field uriField;
    
    TrieMatcher<Rule> * methodStringMatcher;
    // DFAMatcher<Rule> * methodDFAMatcher;
    IntRangeMatcher<Rule> * methodLengthMatcher;
    
    TrieMatcher<Rule> * filenameStringMatcher;
    DFAMatcher<Rule> * filenameDFAMatcher;
    IntRangeMatcher<Rule> * filenameLengthMatcher;
    
    TrieMatcher<Rule> * anydirStringMatcher;
    DFAMatcher<Rule> * anydirDFAMatcher;
    IntRangeMatcher<Rule> * anydirLengthMatcher;
    
    vector<TrieMatcher<Rule> *> dirStringMatcherVector;
    
    // TrieMatcher<DictKeyData *> * varnameStringMatcher;
    // vector<TrieMatcher<UINT32_T> *> * varStringGroupMatcherVector;
    // vector<DFAMatcher<UINT32_T> *> * varRegexGroupMatcherVector;
    // vector<IntRangeMatcher<UINT32_T> *> * varLengthGroupMatcherVector;
    
    TrieMatcher<Rule> * assignmentStringMatcher;
    DFAMatcher<Rule> * assignmentDFAMatcher;
    IntRangeMatcher<Rule> * assignmentLengthMatcher;
    
    TrieMatcher<Rule> * uriStringMatcher;
    DFAMatcher<Rule> * uriDFAMatcher;
    IntRangeMatcher<Rule> * uriLengthMatcher;
    
    TrieMatcher<DictKeyData *> * headernameStringMatcher;
    TrieMatcher<UINT32_T> * headerStringGroupMatcher;
    DFAMatcher<UINT32_T> * headerRegexGroupMatcher;
    IntRangeMatcher<UINT32_T> * headerLengthGroupMatcher;
    DictKeyData * headerDictKeyData;
    
    TrieMatcher<DictKeyData *> * varnameStringMatcher;
    TrieMatcher<UINT32_T> * varStringGroupMatcher;
    DFAMatcher<UINT32_T> * varRegexGroupMatcher;
    IntRangeMatcher<UINT32_T> * varLengthGroupMatcher;
    DictKeyData * varDictKeyData;
    
    vector<vector<UINT16_T> *> csalgoColumnMatchedRuleVector;
    CSAlgo csalgo;
    
    vector<Field> varNameVector;
    vector<Field> varValueVector;
    
    vector<Field> headerNameVector;
    vector<Field> headerValueVector;
    
    static void csalgoRuleMatchedCallback(const Rule & rule, void * cbParam)
    {
        vector<vector<UINT16_T> *> * matchedRuleVector = (vector<vector<UINT16_T> *> *)cbParam;
        
        (*matchedRuleVector)[rule.columnID]->push_back(rule.ruleID);
    }
    
    class RuleGroupInfo
    {
    public:
        const vector<vector<Rule> *> * ruleVector;
        vector<vector<UINT16_T> *> * matchedRuleVector;
    };
    
    static void csalgoRuleGroupMatchedCallback(const UINT32_T & groupID, void * cbParam)
    {
        RuleGroupInfo * ruleGroupInfo = (RuleGroupInfo *)cbParam;
        
        vector<Rule>::const_iterator regexRuleVectorIt = ((*(ruleGroupInfo->ruleVector))[groupID])->begin();
        while(regexRuleVectorIt != ((*(ruleGroupInfo->ruleVector))[groupID])->end())
        {
            // cout << *regexRuleVectorIt << "\n";
            
            (*(ruleGroupInfo->matchedRuleVector))[(*regexRuleVectorIt).columnID]->push_back((*regexRuleVectorIt).ruleID);
            
            regexRuleVectorIt++;
        }
    }
    
    inline INT32_T alterFieldBeginningPtr(Field * field)
    {
        if(field->parsingState != INPROCESS)
        {
            return 0;
        }
        
        field->dataBegin = buffer->getCurrentDataPtr();
        field->dataEnd = field->dataBegin;
        
        return 0;
    }
    
    inline INT32_T alterFieldEndingPtr(Field * field)
    {
        if(field->parsingState != INPROCESS)
        {
            return 0;
        }
        
        field->dataEnd += 1;
        
        return 0;
    }
    
    inline INT32_T changeFieldState(Field * field)
    {
        if(field->parsingState == FINISHED)
        {
            field->matchingState = STRING_MATCHED | REGEX_MATCHED | LENGTH_MATCHED;
        }
        
        return 0;
    }
    
    inline INT32_T logFields()
    {
        if(logFile != NULL)
        {
            if((methodField.parsingState == INPROCESS || methodField.parsingState == FINISHED) && methodField.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "methodField:\n");
                printField(methodField, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if((varName.parsingState == INPROCESS || varName.parsingState == FINISHED) && varName.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "variable.name:\n");
                printField(varName, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if((varValue.parsingState == INPROCESS || varValue.parsingState == FINISHED) && varValue.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "variable.value:\n");
                printField(varValue, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if((assignmentField.parsingState == INPROCESS || assignmentField.parsingState == FINISHED) && assignmentField.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "assignmentField:\n");
                printField(assignmentField, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if((uriField.parsingState == INPROCESS || uriField.parsingState == FINISHED) && uriField.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "uriField:\n");
                printField(uriField, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if((parseHttpHeaderNameField.parsingState == INPROCESS || parseHttpHeaderNameField.parsingState == FINISHED) && parseHttpHeaderNameField.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "header.name:\n");
                printField(parseHttpHeaderNameField, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if((parseHttpHeaderValueField.parsingState == INPROCESS || parseHttpHeaderValueField.parsingState == FINISHED) && parseHttpHeaderValueField.matchingState == NEVER_MATCHED)
            {
                fprintf(logFile, "header.value:\n");
                printField(parseHttpHeaderValueField, logFile);
                fprintf(logFile, "\n\n");
            }
        }
        
        return 0;
    }
    
    STRING_T dirString;
    
    inline INT32_T storeDirField(Field * field)
    {
        if(field->parsingState == INPROCESS)
        {
            dirString.append((const char *)(field->dataBegin), field->dataEnd - field->dataBegin + 1);
        }
        
        return 0;
    }
    
    virtual INT32_T beforeContextOut()
    {
        if(parseOnly->count == 0 || logFile != NULL)
        {
            alterFieldEndingPtr(&methodField);
            
            storeDirField(&dirField);
            
            alterFieldEndingPtr(&varName);
            alterFieldEndingPtr(&varValue);
            
            alterFieldEndingPtr(&assignmentField);
            alterFieldEndingPtr(&uriField);
            
            alterFieldEndingPtr(&parseHttpHeaderNameField);
            alterFieldEndingPtr(&parseHttpHeaderValueField);
            
            logFields();
        }
        
        if(parseOnly->count == 0 && seqMatch->count == 0)
        {
            incrementalMatch();
        }
        else
        {
            changeFieldState(&methodField);
            
            changeFieldState(&varName);
            changeFieldState(&varValue);
            
            changeFieldState(&assignmentField);
            changeFieldState(&uriField);
            
            changeFieldState(&parseHttpHeaderNameField);
            changeFieldState(&parseHttpHeaderValueField);
        }
        
        return 0;
    }
    
    virtual INT32_T afterContextIn()
    {
        if(parseOnly->count == 0 || logFile != NULL)
        {
            alterFieldBeginningPtr(&methodField);
            alterFieldBeginningPtr(&dirField);
            
            alterFieldBeginningPtr(&varName);
            alterFieldBeginningPtr(&varValue);
            
            alterFieldBeginningPtr(&assignmentField);
            alterFieldBeginningPtr(&uriField);
            
            alterFieldBeginningPtr(&parseHttpHeaderNameField);
            alterFieldBeginningPtr(&parseHttpHeaderValueField);
        }
        
        return 0;
    }
    
    virtual INT32_T finish()
    {
        if(parseOnly->count == 0)
        {
            if(seqMatch->count == 0)
            {
                incrementalMatch();
                performCSAlgo();
            }
            else
            {
                HTTPAnalyzerSeqMatch(methodField, filenameField,
                          dirFieldVector, varNameVector, 
                          varValueVector, headerNameVector,
                          headerValueVector, assignmentField, uriField);
            }
        }
        
        return 0;
    }
    
    inline INT32_T incrementalMatch()
    {
        matchSimpleFieldString(&methodField, methodStringMatcher);
        // matchSimpleFieldRegex(&methodField, methodDFAMatcher);
        matchSimpleFieldLength(&methodField, methodLengthMatcher);
        
        matchFieldPair(&varName, &varValue,
                       varnameStringMatcher, &varDictKeyData,
                       varStringGroupStructVector, varStringGroupMatcher,
                       varRegexGroupStructVector, varRegexGroupMatcher,
                       varLengthGroupStructVector, varLengthGroupMatcher);
        
        matchFieldPair(&parseHttpHeaderNameField, &parseHttpHeaderValueField,
                       headernameStringMatcher, &headerDictKeyData,
                       headerStringGroupStructVector, headerStringGroupMatcher,
                       headerRegexGroupStructVector, headerRegexGroupMatcher,
                       headerLengthGroupStructVector, headerLengthGroupMatcher);
        
        matchSimpleFieldString(&assignmentField, assignmentStringMatcher);
        matchSimpleFieldRegex(&assignmentField, assignmentDFAMatcher);
        matchSimpleFieldLength(&assignmentField, assignmentLengthMatcher);
        
        matchSimpleFieldString(&uriField, uriStringMatcher);
        matchSimpleFieldRegex(&uriField, uriDFAMatcher);
        matchSimpleFieldLength(&uriField, uriLengthMatcher);
                
        return 0;
    }
    
    inline INT32_T performCSAlgo()
    {
        Connection * conn = flow->getConnection();
        
        for(UINT32_T i = 0; i < HTTPAnalyzer::columnNum; i++)
        {
            if(printcs->count > 0)
            {
                if(reassembled->count == 1)
                {
                    fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                }
                else
                {
                    fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                }
            }
            
            csalgo.updateField(i, csalgoColumnMatchedRuleVector[i]);
        }
        
        const std::vector<UINT16_T> * ruleVector = csalgo.getAvailableRule();
        if(ruleVector->size() > 0)
        {
            if(matched == false)
            {
                accMatchedFlowNum++;
            }
            matched = true;
        }
        
        // if(silent->count == 0)
        {
            std::vector<UINT16_T>::const_iterator ruleVectorIt = ruleVector->begin();
            while(ruleVectorIt != ruleVector->end())
            {
                /*
                if(*ruleVectorIt == 501)
                {
                    if(reassembled->count == 1)
                    {
                        fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                    }
                    else
                    {
                        fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                    }
                }
                */
                
                
                if(reassembled->count == 1)
                {
                    fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                }
                else
                {
                    fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                }
                
                fprintf(stdout, "Rule %d matched!\n", *ruleVectorIt);
                
                if(logFile != NULL)
                {
                    fprintf(logFile, "Rule %d matched!\n", *ruleVectorIt);
                }
                
                
                if(ruleMap.find(*ruleVectorIt) == ruleMap.end())
                {
                    ruleMap[*ruleVectorIt] = 1;
                }
                else
                {
                    ruleMap[*ruleVectorIt] += 1;
                }
                
                ruleVectorIt++;
            }
                
            if(logFile != NULL)
            {
                fprintf(logFile, "\n");
            }
        }
        
        resetState();
        
        return 0;
    }
    
    inline INT32_T matchSimpleFieldString(Field * field, TrieMatcher<Rule> * stringMatcher)
    {
        if(field == NULL)
        {
            return -1;
        }
        
        if(field->parsingState == INVALID || (field->matchingState & STRING_MATCHED) != 0)
        {
            return -1;
        }
        
        if(stringMatcher == NULL)
        {
            return -1;
        }
        
        stringMatcher->match(field->dataBegin, field->dataEnd);
        
        if(field->parsingState == FINISHED)
        {
            TRIEState<Rule> trieState;
            trieState = stringMatcher->getCurrentState();
            
            if(trieState.isFinal == true)
            {
                vector<Rule>::const_iterator it = trieState.dataVector->begin();
                while(it != trieState.dataVector->end())
                {
                    // cout << *it << "\n";
                    
                    csalgoColumnMatchedRuleVector[(*it).columnID]->push_back((*it).ruleID);
                    
                    it++;
                }
            }
            
            field->matchingState |= STRING_MATCHED;
        }
        
        return 0;
    }
    
    inline INT32_T matchSimpleFieldRegex(Field * field, DFAMatcher<Rule> * dfaMatcher)
    {
        if(field == NULL)
        {
            return -1;
        }
        
        if(field->parsingState == INVALID || (field->matchingState & REGEX_MATCHED) != 0)
        {
            return -1;
        }
        
        if(dfaMatcher == NULL)
        {
            return -1;
        }
        
        dfaMatcher->match(field->dataBegin, field->dataEnd, csalgoRuleMatchedCallback, &csalgoColumnMatchedRuleVector);
        
        if(field->parsingState == FINISHED)
        {
            dfaMatcher->getCurrentState(csalgoRuleMatchedCallback, &csalgoColumnMatchedRuleVector);
            field->matchingState |= REGEX_MATCHED;
        }
        
        return 0;
    }
    
    inline INT32_T matchSimpleFieldLength(Field * field, IntRangeMatcher<Rule> * lengthMatcher)
    {
        if(field == NULL)
        {
            return -1;
        }
        
        if(field->parsingState == INVALID || (field->matchingState & LENGTH_MATCHED) != 0)
        {
            return -1;
        }
        
        if(lengthMatcher == NULL)
        {
            return -1;
        }
        
        lengthMatcher->matchGt(field->dataEnd - field->dataBegin);
        
        if(field->parsingState == FINISHED)
        {
            vector<IntRangeStruct<Rule>::Pair>::const_iterator first, last;
            lengthMatcher->getGtCurrentState(&first, &last);
            
            vector<IntRangeStruct<Rule>::Pair>::const_iterator it = first;
            while(it != last)
            {
                // cout << (*it).data << "\n";
                
                csalgoColumnMatchedRuleVector[(*it).data.columnID]->push_back((*it).data.ruleID);
                
                it++;
            }
            
            field->matchingState |= LENGTH_MATCHED;
        }
        
        return 0;
    }
    
    inline INT32_T matchFieldArrayString(vector<Field> * arrayFieldVector,
                                         const vector< ArrayMatchingStruct<TrieStruct<Rule> *> > * arrayStringStructVector,
                                         const vector<TrieMatcher<Rule> *> * arrayStringMatcherVector)
    {
        UINT32_T arrayStringStructVectorSize = arrayStringStructVector->size();
        for(UINT32_T i = 0; i < arrayStringStructVectorSize; i++)
        {
            const ArrayMatchingStruct<TrieStruct<Rule> *> * arrayMatchingStruct = &((*arrayStringStructVector)[i]);
            
            UINT32_T idx = 0;
            if(arrayMatchingStruct->index >= 0 && arrayMatchingStruct->index < (INT32_T)(arrayFieldVector->size()))
            {
                idx = arrayMatchingStruct->index;
            }
            else if(arrayMatchingStruct->index < 0 && arrayMatchingStruct->index + (INT32_T)(arrayFieldVector->size()) >= 0)
            {
                idx = arrayMatchingStruct->index + arrayFieldVector->size();
            }
            else
            {
                continue;
            }
            
            if((*arrayFieldVector)[idx].parsingState != FINISHED)
            {
                continue;
            }
            
            TrieMatcher<Rule> * stringMatcher = (*arrayStringMatcherVector)[i];
            stringMatcher->match((*arrayFieldVector)[idx].dataBegin, (*arrayFieldVector)[idx].dataEnd);
            TRIEState<Rule> trieState = stringMatcher->getCurrentState();
            
            if(trieState.isFinal == true)
            {
                vector<Rule>::const_iterator it = trieState.dataVector->begin();
                while(it != trieState.dataVector->end())
                {
                    // cout << *it << "\n";
                    
                    csalgoColumnMatchedRuleVector[(*it).columnID]->push_back((*it).ruleID);
                    
                    it++;
                }
            }
        }
        
        return 0;
    }
    
    inline INT32_T matchFieldPair(Field * first, Field * second, TrieMatcher<DictKeyData *> * nameStringMatcher,
                                  DictKeyData ** dictKeyData,
                                  const vector<TrieStruct<UINT32_T> *> * stringGroupStructVector,
                                  TrieMatcher<UINT32_T> * stringGroupMatcher,
                                  const vector<DFAStruct<UINT32_T> *> * regexGroupStructVector,
                                  DFAMatcher<UINT32_T> * regexGroupMatcher,
                                  const vector<IntRangeStruct<UINT32_T> *> * lengthGroupStructVector,
                                  IntRangeMatcher<UINT32_T> * lengthGroupMatcher)
    {
		if(nameStringMatcher == NULL)
		{
			return 0;
		}

        if(first->parsingState == INVALID)
        {
            return 0;
        }
        else if(first->parsingState == INPROCESS)
        {
            nameStringMatcher->match(first->dataBegin, first->dataEnd);
            return 0;
        }
        else if(first->parsingState == FINISHED && (first->matchingState & STRING_MATCHED) == 0)
        {
            nameStringMatcher->match(first->dataBegin, first->dataEnd);
            TRIEState<DictKeyData *> trieState = nameStringMatcher->getCurrentState();
            
            if(trieState.isFinal == true)
            {
                vector<DictKeyData *>::const_iterator it = trieState.dataVector->begin();
                while(it != trieState.dataVector->end())
                {
                    *dictKeyData = *it;
                    
                    if((*dictKeyData)->stringGroup >= 0)
                    {
                        stringGroupMatcher->init((*stringGroupStructVector)[(*dictKeyData)->stringGroup]);
                    }
                    
                    if((*dictKeyData)->regexGroup >= 0)
                    {
                        regexGroupMatcher->init((*regexGroupStructVector)[(*dictKeyData)->regexGroup]);
                    }
                    
                    if((*dictKeyData)->lengthGroup >= 0)
                    {
                        lengthGroupMatcher->init((*lengthGroupStructVector)[(*dictKeyData)->lengthGroup]);                    
                    }
                    
                    // There should be at most one DictKeyData instance.
                    break;
                }
            }
			else
			{
				*dictKeyData = NULL;
			}
            
            first->matchingState |= STRING_MATCHED;
        }
        
        if(second->parsingState == INVALID || (second->matchingState & (STRING_MATCHED | REGEX_MATCHED | LENGTH_MATCHED)) != 0)
        {
            return 0;
        }
        
        if((first->matchingState & STRING_MATCHED) != 0 && *dictKeyData != NULL)
        {
            if(second->parsingState == INPROCESS)
            {
                if((*dictKeyData)->stringGroup >= 0)
                {
                    stringGroupMatcher->match(second->dataBegin, second->dataEnd);
                }
                
                if((*dictKeyData)->regexGroup >= 0)
                {
                    RuleGroupInfo ruleGroupInfo;
                    ruleGroupInfo.ruleVector = &((*dictKeyData)->regexRuleVector);
                    ruleGroupInfo.matchedRuleVector = &csalgoColumnMatchedRuleVector;
                    regexGroupMatcher->match(second->dataBegin, second->dataEnd, csalgoRuleGroupMatchedCallback, &ruleGroupInfo);
                }
                
                if((*dictKeyData)->lengthGroup >= 0)
                {
                    lengthGroupMatcher->matchGt(second->dataEnd - second->dataBegin);
                }
            }
            else if(second->parsingState == FINISHED)
            {
                if((*dictKeyData)->stringGroup >= 0)
                {
                    stringGroupMatcher->match(second->dataBegin, second->dataEnd);
                    TRIEState<UINT32_T> tState = stringGroupMatcher->getCurrentState();
                    
                    if(tState.isFinal == true)
                    {
                        vector<UINT32_T>::const_iterator tStateDataVectorIt = tState.dataVector->begin();
                        while(tStateDataVectorIt != tState.dataVector->end())
                        {
                            vector<Rule>::const_iterator stringRuleVectorIt = ((*dictKeyData)->stringRuleVector[*tStateDataVectorIt])->begin();
                            while(stringRuleVectorIt != ((*dictKeyData)->stringRuleVector[*tStateDataVectorIt])->end())
                            {
                                // cout << *stringRuleVectorIt << "\n";
                                
                                csalgoColumnMatchedRuleVector[(*stringRuleVectorIt).columnID]->push_back((*stringRuleVectorIt).ruleID);
                                
                                stringRuleVectorIt++;
                            }
                            
                            tStateDataVectorIt++;
                        }
                    }

					second->matchingState |= STRING_MATCHED;
                }
                
                if((*dictKeyData)->regexGroup >= 0)
                {
                    RuleGroupInfo ruleGroupInfo;
                    ruleGroupInfo.ruleVector = &((*dictKeyData)->regexRuleVector);
                    ruleGroupInfo.matchedRuleVector = &csalgoColumnMatchedRuleVector;
                    regexGroupMatcher->match(second->dataBegin, second->dataEnd, csalgoRuleGroupMatchedCallback, &ruleGroupInfo);
                    regexGroupMatcher->getCurrentState(csalgoRuleGroupMatchedCallback, &ruleGroupInfo);

					second->matchingState |= REGEX_MATCHED;
                }
                
                if((*dictKeyData)->lengthGroup >= 0)
                {
                    vector<IntRangeStruct<UINT32_T>::Pair>::const_iterator first, last;
                    lengthGroupMatcher->matchGt(second->dataEnd - second->dataBegin);
                    lengthGroupMatcher->getGtCurrentState(&first, &last);
                    
                    vector<IntRangeStruct<UINT32_T>::Pair>::const_iterator lengthDataVectorIt = first;
                    while(lengthDataVectorIt != last)
                    {
                        vector<Rule>::const_iterator lengthRuleVectorIt = ((*dictKeyData)->lengthRuleVector[(*lengthDataVectorIt).data])->begin();
                        while(lengthRuleVectorIt != ((*dictKeyData)->lengthRuleVector[(*lengthDataVectorIt).data])->end())
                        {
                            // cout << *lengthRuleVectorIt << "\n";
                            
                            csalgoColumnMatchedRuleVector[(*lengthRuleVectorIt).columnID]->push_back((*lengthRuleVectorIt).ruleID);
                            
                            lengthRuleVectorIt++;
                        }
                        
                        lengthDataVectorIt++;
                    }

					second->matchingState |= LENGTH_MATCHED;
                }
            }
        }
        else
        {
            changeFieldState(second);
        }
        
        return 0;
    }

    inline INT32_T parseHttpBody(Buffer * buffer, ExpectBody expectBody)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        switch(deliveryMode)
        {
        case CONTENT_LENGTH:
            if(contentLength < 0)
            {
                buffer->skipFlow();
            }
            else
            {
                buffer->skip(contentLength);
            }
            break;
        case CHUNKED:
            parseHttpChunks(buffer);
            break;
        case MULTIPART:
            ReportError(flow->getConnection(), "MULTIPART is not supported now!");
            // fprintf(stdout, "MULTIPART is not supported now!\n");
            break;
        default:
            parseHttpUnknownbody(buffer, expectBody);
            break;
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpChunk(Buffer * buffer, UINT32_T & chunkLength)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        STRING_T line = buffer->readLine(CRLF_OR_LF);
        
        chunkLength = strtol(line.c_str(), NULL, 16);
        // DEBUG_WRAP(DebugMessage("chunkLength = %d\n", chunkLength));
        
        if(chunkLength > 0)
        {
            buffer->skip(chunkLength);
            buffer->readLine(CRLF_OR_LF);
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpChunks(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        UINT32_T chunkLength = 0;
        do
        {
            parseHttpChunk(buffer, chunkLength);
        }while(chunkLength != 0);
        
        // headers:    HTTP_Headers;
        parseHttpHeaders(buffer);
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    // The following two member variables can be used in parseHttpHeader() only.
    Field parseHttpHeaderNameField;
    Field parseHttpHeaderValueField;
    
    inline INT32_T parseHttpHeader(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        UINT8_T * pHeaderName = headerName;
        UINT8_T * pHeaderValue = headerValue;
        
        parseHttpHeaderNameField.reset();
        parseHttpHeaderValueField.reset();
        
        parseHttpHeaderNameField.dataBegin = buffer->getCurrentDataPtr();
        parseHttpHeaderNameField.dataEnd = buffer->getCurrentDataPtr();
        UINT8_T ch = buffer->readUInt8();
        
        if(ch == '\n')
        {
            return buffer->getByteCount() - byteCountBegin;
        }
        
        parseHttpHeaderNameField.dataEnd = buffer->getCurrentDataPtr();
        UINT8_T ch1 = buffer->readUInt8();
        
        if(ch == '\r' && ch1 == '\n')
        {
            return buffer->getByteCount() - byteCountBegin;
        }
        
        parseHttpHeaderNameField.parsingState = INPROCESS;
        
        *pHeaderName = ch;
        pHeaderName++;
        ch = ch1;
        while(ch != ':' && ch != ' ' && ch != '\t')
        {
            if(pHeaderName - headerName < sizeof(headerName) - 1)
            {
                *pHeaderName = ch;
                pHeaderName++;
            }
            
            parseHttpHeaderNameField.dataEnd = buffer->getCurrentDataPtr();
            ch = buffer->readUInt8();
        }
        *pHeaderName = '\0';
        parseHttpHeaderNameField.parsingState = FINISHED;
        
        if(ch != ':')
        {
            ReportError(flow->getConnection(), "HTTP header ':' error!");
            // fprintf(stdout, "HTTP header ':' error!\n");
        }
        
        parseHttpHeaderValueField.dataBegin = buffer->getCurrentDataPtr();
        parseHttpHeaderValueField.dataEnd = buffer->getCurrentDataPtr();
    	ch = buffer->readUInt8();
        while(ch == ' ' || ch == '\t')
        {
            parseHttpHeaderValueField.dataBegin = buffer->getCurrentDataPtr();
            parseHttpHeaderValueField.dataEnd = buffer->getCurrentDataPtr();
            ch = buffer->readUInt8();
        }
        
        parseHttpHeaderValueField.parsingState = INPROCESS;
        parseHttpHeaderValueField.dataEnd = buffer->getCurrentDataPtr();
        
        if(ch != '\n')
        {
            UINT8_T * chPtr = parseHttpHeaderValueField.dataBegin;
            UINT8_T * ch1Ptr = buffer->getCurrentDataPtr();
            
        	ch1 = buffer->readUInt8();
            while(ch1 != '\n')
            {
                if(pHeaderValue - headerValue < sizeof(headerValue) - 1)
                {
                    *pHeaderValue = ch;
                    pHeaderValue++;
                }
                
                chPtr = ch1Ptr;
                parseHttpHeaderValueField.dataEnd = chPtr;
                ch1Ptr = buffer->getCurrentDataPtr();
                
        		ch = ch1;
                ch1 = buffer->readUInt8();
            }
            
            if(ch != '\r')
            {
                parseHttpHeaderValueField.dataEnd = ch1Ptr;
            }
        }
        
        *pHeaderValue = '\0';
        parseHttpHeaderValueField.parsingState = FINISHED;
        
        if(parseHttpHeaderValueField.parsingState == FINISHED)
        {
            if(logFile != NULL)
            {
                fprintf(logFile, "header.name:\n");
                printField(parseHttpHeaderNameField, logFile);
                fprintf(logFile, "\n\n");
                
                fprintf(logFile, "header.value:\n");
                printField(parseHttpHeaderValueField, logFile);
                fprintf(logFile, "\n\n");
            }
            
            if(parseOnly->count == 0)
            {
                if(seqMatch->count == 0)
                {
                    matchFieldPair(&parseHttpHeaderNameField, &parseHttpHeaderValueField,
                               headernameStringMatcher, &headerDictKeyData,
                               headerStringGroupStructVector, headerStringGroupMatcher,
                               headerRegexGroupStructVector, headerRegexGroupMatcher,
                               headerLengthGroupStructVector, headerLengthGroupMatcher);
                }
                else
                {
                    headerNameVector.push_back(parseHttpHeaderNameField);
                    headerValueVector.push_back(parseHttpHeaderValueField);
                }
            }
            else
            {
                changeFieldState(&parseHttpHeaderNameField);
                changeFieldState(&parseHttpHeaderValueField);
            }
        }
        
        if (stricmp((char *)headerName, "CONTENT-LENGTH") == 0)
        {
            contentLength = strtol((char *)headerValue, NULL, 10);
            if(contentLength < 0)
            {
                ReportError(flow->getConnection(), "HTTP Content Length < 0 !");
            }
            deliveryMode = CONTENT_LENGTH;
        }
        else if(stricmp((char *)headerName, "TRANSFER-ENCODING") == 0)
        {
            if (stricmp((char *)headerValue, "CHUNKED") == 0)
            {
                deliveryMode = CHUNKED;
            }
        }
        /* 空语句，暂时注释掉
        else if(stricmp((char *)headerName, "CONTENT-TYPE") == 0)
        {
            if(stricmp((char *)headerValue, "MULTIPART") == 0)
            {
            }
        }
        */
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpHeaders(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        UINT32_T length;
        
        do
        {
            length = parseHttpHeader(buffer);
        }while(length > 2);
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpMessage(Buffer * buffer, ExpectBody expectBody)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        // headers:    HTTP_Headers;
        parseHttpHeaders(buffer);
        
        if(expectBody != BODY_NOT_EXPECTED)
        {
            parseHttpBody(buffer, expectBody);
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpPdu(Buffer * buffer, FlowDir dir)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
            
        contentLength = 0;
        deliveryMode = UNKNOWN_DELIVERY_MODE;
                
        if(dir == ORIG_TO_RESP)
        {
            parseHttpRequest(buffer);
        }
        else
        {
            parseHttpReply(buffer);
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline ExpectBody expectReplyBody(UINT32_T replyStatus)
    {
        // TODO: check if the request is "HEAD"
        if ((replyStatus >= 100 && replyStatus < 200) ||
             replyStatus == 204 || replyStatus == 304 )
        {
            return BODY_NOT_EXPECTED;
        }
        
        return BODY_EXPECTED;
    }
    
    inline INT32_T parseHttpReply(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        UINT32_T statusNum = 0;
        
        parseHttpReplyLine(buffer, &statusNum);
        parseHttpMessage(buffer, expectReplyBody(statusNum));
            
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpReplyLine(Buffer * buffer, UINT32_T * statusNum)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        // version:    HTTP_Version;
        UINT8_T version[5];
        buffer->readArray(version, 5);
        
        if(_strnicmp((INT8_T *)version, "HTTP/", 5) != 0)
        {
            ReportError(flow->getConnection(), "HTTP Version error!");
            // fprintf(stdout, "HTTP Version error!\n");
        }
        
        UINT8_T ch = buffer->readUInt8();
        while(ch >= '0' && ch <= '9')
        {
            ch = buffer->readUInt8();
        }
        
        ch = buffer->readUInt8();
        while(ch >= '0' && ch <= '9')
        {
            ch = buffer->readUInt8();
        }
        
        while(ch == ' ' || ch == '\t')
        {
            ch = buffer->readUInt8();
        }
        
        // status:        HTTP_Status;
        UINT8_T status[4];
    	status[0] = ch;
        buffer->readArray(status + 1, 2);
        status[3] = '\0';
        *statusNum = strtol((INT8_T *)status, NULL, 10);
        
        ch = buffer->readUInt8();
        while(ch == ' ' || ch == '\t')
        {
            ch = buffer->readUInt8();
        }
        
        while(ch != '\n')
        {
            ch = buffer->readUInt8();
        }    
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpRequest(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
            
        parseHttpRequestLine(buffer);
    
        parseHttpMessage(buffer, BODY_MAYBE);
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpRequestLine(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        // method:        HTTP_TOKEN;
        methodField.reset();
        methodField.dataBegin = buffer->getCurrentDataPtr();
		methodField.dataEnd = buffer->getCurrentDataPtr();
        UINT8_T ch = buffer->readUInt8();
        while(ch != '(' && ch != ')' && ch != '<' && ch != '>'  && ch != '@'  &&
              ch != ',' && ch != ';' && ch != ':' && ch != '\\' && ch != '\"' && 
              ch != '/' && ch != '[' && ch != ']' && ch != '?'  && ch != '='  && 
              ch != '{' && ch != '}' && ch != ' ' && ch != '\t')
        {
            methodField.parsingState = INPROCESS;
            methodField.dataEnd = buffer->getCurrentDataPtr();
            ch = buffer->readUInt8();
        }
        
        if(methodField.parsingState == INPROCESS)
        {
            methodField.parsingState = FINISHED;
        }
        
        while(ch == ' ' || ch == '\t')
        {
            ch = buffer->readUInt8();
        }
        
        buffer->pushBack(ch);
        parseHttpUri(buffer);
        
        ch = buffer->readUInt8();
        while(ch == ' ' || ch == '\t')
        {
            ch = buffer->readUInt8();
        }
        
        buffer->pushBack(ch);
        
        // version:    HTTP_Version;
        UINT8_T version[5];
        buffer->readArray(version, 5);
        if(_strnicmp((INT8_T *)version, "HTTP/", 5) != 0)
        {
            ReportError(flow->getConnection(), "HTTP Version error!");
            // fprintf(stdout, "HTTP Version error!\n");
            
            UINT8_T * p = version;
            while(p < version + 5 && *p != '\n')
            {
                p++;
            }
            
            if(*p == '\n')
            {
                p += 1;
                while(p < version + 5)
                {
                    buffer->pushBack(*p);
                    p++;
                }
                
                return buffer->getByteCount() - byteCountBegin;
            }
            else
            {
                ch = *p;
    		    goto http_request_line_crlf;
    		}
        }
        
        ch = buffer->readUInt8();
        while(ch >= '0' && ch <= '9')
        {
            ch = buffer->readUInt8();
        }
        
        ch = buffer->readUInt8();
        while(ch >= '0' && ch <= '9')
        {
            ch = buffer->readUInt8();
        }
    
    http_request_line_crlf:
        while(ch != '\n')
        {
            ch = buffer->readUInt8();
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    inline INT32_T parseHttpUnknownbody(Buffer * buffer, ExpectBody expectBody)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        if(expectBody == BODY_EXPECTED)
        {
            // fprintf(stdout, "Unknown http body!\n");
    		buffer->skipFlow();
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
    
    Field varName;
    Field varValue;
    
    Field dirField;
    
    inline INT32_T parseHttpUri(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        dirFieldVector.clear();
        dirString.clear();
        dirField.reset();
        
        uriField.reset();
        uriField.dataBegin = buffer->getCurrentDataPtr();
        uriField.dataEnd = buffer->getCurrentDataPtr();
        uriField.parsingState = INPROCESS;

		dirField.dataBegin = buffer->getCurrentDataPtr();
		dirField.dataEnd = buffer->getCurrentDataPtr();
        
        UINT8_T ch = buffer->readUInt8();
    	if(ch == '/')
    	{
    	    dirField.dataBegin = buffer->getCurrentDataPtr();
    	    dirField.dataEnd = buffer->getCurrentDataPtr();
    	    uriField.dataEnd = buffer->getCurrentDataPtr();
    	    
            ch = buffer->readUInt8();
    	    goto http_uri_abs_path;
    	}
    	else if(!INSET(PROTO, ch))
    	{
    	    goto http_uri_abs_path;
    	}
    	else
    	{
    	    while(INSET(PROTO, ch))
    	    {
    	        uriField.dataEnd = buffer->getCurrentDataPtr();
    	        
    	        ch = buffer->readUInt8();
            }
            
            UINT8_T str[3];
            str[0] = ch;
            buffer->readArray(str + 1, 2);
            
            uriField.dataEnd = buffer->getCurrentDataPtr();
                        
            if(_strnicmp((INT8_T *)str, "://", 3) != 0)
            {
                ReportError(flow->getConnection(), "HTTP URI error!");
                // fprintf(stdout, "HTTP URI error!\n");
            }
        }
        
        uriField.dataEnd = buffer->getCurrentDataPtr();
        dirField.dataBegin = buffer->getCurrentDataPtr();
        dirField.dataEnd = buffer->getCurrentDataPtr();
        
        ch = buffer->readUInt8();
        while(INSET(HOST, ch))
    	{
    	    uriField.dataEnd = buffer->getCurrentDataPtr();
    	    dirField.dataBegin = buffer->getCurrentDataPtr();
    	    dirField.dataEnd = buffer->getCurrentDataPtr();
    	    
    	    ch = buffer->readUInt8();
        }
        
        if(ch == '/')
    	{
    	    dirField.dataBegin = buffer->getCurrentDataPtr();
    	    dirField.dataEnd = buffer->getCurrentDataPtr();
    	    uriField.dataEnd = buffer->getCurrentDataPtr();
    	    
    	    ch = buffer->readUInt8();
    	    goto http_uri_abs_path;
    	}
    
    http_uri_abs_path:

        assignmentField.reset();
        
        UirParsingState state = ABS_PATH;
        
        while(state != FINISH && state != BAD)
        {
            switch(state)
            {
            case ABS_PATH:
                if(ch == '#')
                {
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_FRAGMENT;
                }
                else if(ch == '?')
                {
                    varName.reset();
                    varValue.reset();
                    varName.dataBegin = buffer->getCurrentDataPtr();
                    varName.dataEnd = buffer->getCurrentDataPtr();
                    assignmentField.dataBegin = buffer->getCurrentDataPtr();
                    assignmentField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_QUERY;
                }
                else if(ch == '/')
                {
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    dirField.dataBegin = buffer->getCurrentDataPtr();
                    dirField.dataEnd = buffer->getCurrentDataPtr();
                    ch = buffer->readUInt8();
                    state = ABS_PATH;
                }
                else if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    if(uriField.parsingState == INPROCESS)
                    {
                        uriField.parsingState = FINISHED;
                    }
                    
                    state = FINISH;
                }
                else/* if(INSET(DIR, ch)) */
                {
                    // buffer->pushBack(ch);
                    
                    state = DIRECTORY;
                }
                /*
                else
                {
                    state = BAD;
                }
                */
                break;
            case DIRECTORY:
                /*
                if(INSET(DIR, ch))
                {
                    ch = buffer->readUInt8();
                    state = DIRECTORY;
                }
                else */
                
                if(ch == '/')
                {
                    dirField.parsingState = FINISHED;
                    
                    if(parseOnly->count == 0 || logFile != NULL)
                    {
                        if(dirString.length() > 0)
                        {
                            dirString.append((const char *)(dirField.dataBegin), dirField.dataEnd - dirField.dataBegin);
                            dirField.dataBegin = (UINT8_T *)(dirString.c_str());
                            dirField.dataEnd = dirField.dataBegin + dirString.length();
                        }
                        
                        if(reassembled->count == 0)
                        {
                            dirField.makePermanent();
                        }
                        dirField.parsingState = FINISHED;
                        
                        dirFieldVector.push_back(dirField);
                    }
                    
                    dirField.reset();
                    dirString.clear();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    dirField.dataBegin = buffer->getCurrentDataPtr();
					dirField.dataEnd = buffer->getCurrentDataPtr();
                    ch = buffer->readUInt8();
                    state = ABS_PATH;
                }
                else if(ch == '#')
                {
                    dirField.parsingState = FINISHED;
                    
                    if(parseOnly->count == 0 || logFile != NULL)
                    {
                        if(dirString.length() > 0)
                        {
                            dirString.append((const char *)(dirField.dataBegin), dirField.dataEnd - dirField.dataBegin);
                            dirField.dataBegin = (UINT8_T *)(dirString.c_str());
                            dirField.dataEnd = dirField.dataBegin + dirString.length();
                        }
                        
                        if(reassembled->count == 0)
                        {
                            dirField.makePermanent();
                        }
                        dirField.parsingState = FINISHED;
                        
                        dirFieldVector.push_back(dirField);
                    }
                    
                    dirField.reset();
                    dirString.clear();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_FRAGMENT;
                }
                else if(ch == '?')
                {
                    dirField.parsingState = FINISHED;
                    
                    if(parseOnly->count == 0 || logFile != NULL)
                    {
                        if(dirString.length() > 0)
                        {
                            dirString.append((const char *)(dirField.dataBegin), dirField.dataEnd - dirField.dataBegin);
                            dirField.dataBegin = (UINT8_T *)(dirString.c_str());
                            dirField.dataEnd = dirField.dataBegin + dirString.length();
                        }
                        
                        if(reassembled->count == 0)
                        {
                            dirField.makePermanent();
                        }
                        dirField.parsingState = FINISHED;
                        
                        dirFieldVector.push_back(dirField);
                    }
                    
                    dirField.reset();
                    dirString.clear();
                    
                    varName.reset();
                    varValue.reset();
                    varName.dataBegin = buffer->getCurrentDataPtr();
                    varName.dataEnd = buffer->getCurrentDataPtr();
                    assignmentField.dataBegin = buffer->getCurrentDataPtr();
                    assignmentField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_QUERY;
                }
                else if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    dirField.parsingState = FINISHED;
                    
                    if(parseOnly->count == 0 || logFile != NULL)
                    {
                        if(dirString.length() > 0)
                        {
                            dirString.append((const char *)(dirField.dataBegin), dirField.dataEnd - dirField.dataBegin);
                            dirField.dataBegin = (UINT8_T *)(dirString.c_str());
                            dirField.dataEnd = dirField.dataBegin + dirString.length();
                        }
                        
                        if(reassembled->count == 0)
                        {
                            dirField.makePermanent();
                        }
                        dirField.parsingState = FINISHED;
                        
                        dirFieldVector.push_back(dirField);
                    }
                    
                    dirField.reset();
                    dirString.clear();
                    
                    if(uriField.parsingState == INPROCESS)
                    {
                        uriField.parsingState = FINISHED;
                    }
                    
                    state = FINISH;
                }
                else
                {
                    /* state = BAD; */
					dirField.parsingState = INPROCESS;
                    dirField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = DIRECTORY;
                }
                break;
            case EXPECT_QUERY:
                if(ch == '&')
                {
                    if(logFile != NULL)
                    {
                        fprintf(logFile, "variable.name:\n");
                        printField(varName, logFile);
                        fprintf(logFile, "\n\n");
                        
                        fprintf(logFile, "variable.value:\n");
                        printField(varValue, logFile);
                        fprintf(logFile, "\n\n");
                    }
                    
                    if(parseOnly->count == 0)
                    {
                        if(seqMatch->count == 0)
                        {
                            matchFieldPair(&varName, &varValue,
                                       varnameStringMatcher, &varDictKeyData,
                                       varStringGroupStructVector, varStringGroupMatcher,
                                       varRegexGroupStructVector, varRegexGroupMatcher,
                                       varLengthGroupStructVector, varLengthGroupMatcher);
                        }
                        else
                        {
                            varNameVector.push_back(varName);
                            varValueVector.push_back(varValue);
                        }
                    }
                    else
                    {
                        changeFieldState(&varName);
                        changeFieldState(&varValue);
                    }
                    
                    varName.reset();
                    varValue.reset();
                    varName.dataBegin = buffer->getCurrentDataPtr();
                    varName.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_QUERY;
                }
                /*
                else if(INSET(VAR, ch))
                {
                    buffer->pushBack(ch);
                    state = VAR_NAME;
                }
                */
                else if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    if(logFile != NULL)
                    {
                        fprintf(logFile, "variable.name:\n");
                        printField(varName, logFile);
                        fprintf(logFile, "\n\n");
                        
                        fprintf(logFile, "variable.value:\n");
                        printField(varValue, logFile);
                        fprintf(logFile, "\n\n");
                    }
                    
                    if(parseOnly->count == 0)
                    {
                        if(seqMatch->count == 0)
                        {
                            matchFieldPair(&varName, &varValue,
                                       varnameStringMatcher, &varDictKeyData,
                                       varStringGroupStructVector, varStringGroupMatcher,
                                       varRegexGroupStructVector, varRegexGroupMatcher,
                                       varLengthGroupStructVector, varLengthGroupMatcher);
                        }
                        else
                        {
                            varNameVector.push_back(varName);
                            varValueVector.push_back(varValue);
                        }
                    }
                    else
                    {
                        changeFieldState(&varName);
                        changeFieldState(&varValue);
                    }
                    
                    if(assignmentField.parsingState == INPROCESS)
                    {
                        assignmentField.parsingState = FINISHED;
                    }
                    
                    if(uriField.parsingState == INPROCESS)
                    {
                        uriField.parsingState = FINISHED;
                    }
                    
                    state = FINISH;
                }
                else
                {
                    /* state = BAD; */
                    // buffer->pushBack(ch);                    
                    state = VAR_NAME;
                }
                break;
            case EXPECT_FRAGMENT:
                if(INSET(FRAGMENT, ch))
                {
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_FRAGMENT;
                }
                else if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    if(uriField.parsingState == INPROCESS)
                    {
                        uriField.parsingState = FINISHED;
                    }
                    
                    state = FINISH;
                }
                else
                {
                    state = BAD;
                }
                break;
            case VAR_NAME:
                /*
                if(INSET(VAR, ch))
                {
                    ch = buffer->readUInt8();
                    state = VAR_NAME;
                }
                else */
                if(ch == '=')
                {
                    if(varName.parsingState == INPROCESS)
                    {
                        varName.parsingState = FINISHED;
                    }
                    
                    assignmentField.parsingState = INPROCESS;
                    assignmentField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    varValue.dataBegin = buffer->getCurrentDataPtr();
                    varValue.dataEnd = buffer->getCurrentDataPtr();
                    ch = buffer->readUInt8();
                    state = VAR_VALUE;
                }
                else if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    if(varName.parsingState == INPROCESS)
                    {
                        varName.parsingState = FINISHED;
                    }
                    
                    if(assignmentField.parsingState == INPROCESS)
                    {
                        assignmentField.parsingState = FINISHED;
                    }
                    
                    if(uriField.parsingState == INPROCESS)
                    {
                        uriField.parsingState = FINISHED;
                    }
                    
                    state = FINISH;
                }
                else
                {
                    /* state = BAD; */
                    varName.parsingState = INPROCESS;
                    varName.dataEnd = buffer->getCurrentDataPtr();
                    assignmentField.parsingState = INPROCESS;
                    assignmentField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = VAR_NAME;
                }
                break;
            case VAR_VALUE:
                /*
                if(INSET(VALUE, ch))
                {
                    ch = buffer->readUInt8();
                    state = VAR_VALUE;
                }
                else */
                if(ch == '#')
                {
                    varValue.parsingState = FINISHED;
                    
                    if(logFile != NULL)
                    {
                        fprintf(logFile, "variable.name:\n");
                        printField(varName, logFile);
                        fprintf(logFile, "\n\n");
                        
                        fprintf(logFile, "variable.value:\n");
                        printField(varValue, logFile);
                        fprintf(logFile, "\n\n");
                    }
                    
                    if(parseOnly->count == 0)
                    {
                        if(seqMatch->count == 0)
                        {
                            matchFieldPair(&varName, &varValue,
                                       varnameStringMatcher, &varDictKeyData,
                                       varStringGroupStructVector, varStringGroupMatcher,
                                       varRegexGroupStructVector, varRegexGroupMatcher,
                                       varLengthGroupStructVector, varLengthGroupMatcher);
                        }
                        else
                        {
                            varNameVector.push_back(varName);
                            varValueVector.push_back(varValue);
                        }
                    }
                    else
                    {
                        changeFieldState(&varName);
                        changeFieldState(&varValue);
                    }
                    
                    if(assignmentField.parsingState == INPROCESS)
                    {
                        assignmentField.parsingState = FINISHED;
                    }
                    
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_FRAGMENT;
                }
                else if(ch == '&')
                {
                    varValue.parsingState = FINISHED;
                    
                    if(logFile != NULL)
                    {
                        fprintf(logFile, "variable.name:\n");
                        printField(varName, logFile);
                        fprintf(logFile, "\n\n");
                        
                        fprintf(logFile, "variable.value:\n");
                        printField(varValue, logFile);
                        fprintf(logFile, "\n\n");
                    }
                    
                    if(parseOnly->count == 0)
                    {
                        if(seqMatch->count == 0)
                        {
                            matchFieldPair(&varName, &varValue,
                                       varnameStringMatcher, &varDictKeyData,
                                       varStringGroupStructVector, varStringGroupMatcher,
                                       varRegexGroupStructVector, varRegexGroupMatcher,
                                       varLengthGroupStructVector, varLengthGroupMatcher);
                        }
                        else
                        {
                            varNameVector.push_back(varName);
                            varValueVector.push_back(varValue);
                        }
                    }
                    else
                    {
                        changeFieldState(&varName);
                        changeFieldState(&varValue);
                    }
                    
                    varName.reset();
                    varValue.reset();
                    varName.dataBegin = buffer->getCurrentDataPtr();
                    varName.dataEnd = buffer->getCurrentDataPtr();
                    assignmentField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = EXPECT_QUERY;
                }
                else if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    if(varValue.parsingState == INPROCESS)
                    {
                        varValue.parsingState = FINISHED;
                    }
                    
                    if(logFile != NULL)
                    {
                        fprintf(logFile, "variable.name:\n");
                        printField(varName, logFile);
                        fprintf(logFile, "\n\n");
                        
                        fprintf(logFile, "variable.value:\n");
                        printField(varValue, logFile);
                        fprintf(logFile, "\n\n");
                    }
                    
                    if(parseOnly->count == 0)
                    {
                        if(seqMatch->count == 0)
                        {
                            matchFieldPair(&varName, &varValue,
                                       varnameStringMatcher, &varDictKeyData,
                                       varStringGroupStructVector, varStringGroupMatcher,
                                       varRegexGroupStructVector, varRegexGroupMatcher,
                                       varLengthGroupStructVector, varLengthGroupMatcher);
                        }
                        else
                        {
                            varNameVector.push_back(varName);
                            varValueVector.push_back(varValue);
                        }
                    }
                    else
                    {
                        changeFieldState(&varName);
                        changeFieldState(&varValue);
                    }
                    
                    if(assignmentField.parsingState == INPROCESS)
                    {
                        assignmentField.parsingState = FINISHED;
                    }
                    
                    if(uriField.parsingState == INPROCESS)
                    {
                        uriField.parsingState = FINISHED;
                    }
                    
                    state = FINISH;
                }
                else
                {
                    /* state = BAD; */
                    varValue.parsingState = INPROCESS;
                    varValue.dataEnd = buffer->getCurrentDataPtr();
                    assignmentField.dataEnd = buffer->getCurrentDataPtr();
                    uriField.dataEnd = buffer->getCurrentDataPtr();
                    
                    ch = buffer->readUInt8();
                    state = VAR_VALUE;
                }
                break;
            case FINISH:
                break;
            default:
                break;
            }
        }
        
        if(state == BAD)
        {
            assignmentField.dataEnd = buffer->getCurrentDataPtr();
            uriField.dataEnd = buffer->getCurrentDataPtr();
            
            if(assignmentField.parsingState == INPROCESS)
            {
                assignmentField.parsingState = FINISHED;
            }
            
            if(uriField.parsingState == INPROCESS)
            {
                uriField.parsingState = FINISHED;
            }
        }
        
        if(dirFieldVector.size() > 0)
        {
            filenameField = dirFieldVector[dirFieldVector.size() - 1];
        }
        
        if(dirFieldVector.size() > 0 && seqMatch->count == 0)
        {
            if(logFile != NULL)
            {
                fprintf(logFile, "filenameField:\n");
                printField(filenameField, logFile);
                fprintf(logFile, "\n\n");
            }
            
            matchSimpleFieldString(&filenameField, filenameStringMatcher);
            matchSimpleFieldRegex(&filenameField, filenameDFAMatcher);
            matchSimpleFieldLength(&filenameField, filenameLengthMatcher);
            
            // The last element in dirFieldVector is filename, which doesn't need to be matched.
            for(UINT32_T i = 0; dirFieldVector.size() > 1 && i < dirFieldVector.size() - 1; i++)
            {
                matchSimpleFieldString(&(dirFieldVector[i]), anydirStringMatcher);
                matchSimpleFieldRegex(&(dirFieldVector[i]), anydirDFAMatcher);
                matchSimpleFieldLength(&(dirFieldVector[i]), anydirLengthMatcher);
            }
            
            matchFieldArrayString(&dirFieldVector, &dirStringStructVector, &dirStringMatcherVector);
            
            for(UINT32_T i = 0; i < dirFieldVector.size(); i++)
            {
                if(logFile != NULL)
                {
                    fprintf(logFile, "dirFieldVector[%d]:\n", i);
                    printField(dirFieldVector[i], logFile);
                    fprintf(logFile, "\n\n");
                }
                
                dirFieldVector[i].releaseMemory();
            }
            
            dirFieldVector.clear();
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }
};

#endif
