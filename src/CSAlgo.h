#ifndef _CANDIDATE_SELECTION_ALGORITHM_H_
#define _CANDIDATE_SELECTION_ALGORITHM_H_

#include <vector>

#include "NetShield.h"

class CSAlgo
{
public:
    CSAlgo();
    ~CSAlgo();
    
    INT32_T init(const UINT8_T * ruleMatrix, const UINT32_T * ruleGrpSID, UINT32_T columnNum, UINT32_T ruleNum);
    INT32_T reset();
    
    /*
    要求matchedRule为升序表。
    */
    INT32_T updateField(const UINT16_T fieldNo, std::vector<UINT16_T> * matchedRule);
    const std::vector<UINT16_T> * getAvailableRule()const;
    
protected:
    const UINT8_T * ruleMatrix;
    const UINT32_T * ruleGrpSID;
    UINT32_T ruleNum;
    UINT32_T columnNum;
    
    std::vector<UINT16_T> s;
    UINT32_T currentField;
};

#endif
