#include <cassert>
#include <algorithm>

#include "NetShield.h"
#include "Global.h"
#include "CSAlgo.h"

CSAlgo::CSAlgo()
{
    ruleMatrix = NULL;
    ruleNum = 0;
    columnNum = 0;
    s.reserve(8);
}

CSAlgo::~CSAlgo()
{
}
    
INT32_T CSAlgo::init(const UINT8_T * ruleMatrix, const UINT32_T * ruleGrpSID, UINT32_T columnNum, UINT32_T ruleNum)
{
    assert(ruleMatrix != NULL);
    assert(ruleGrpSID != NULL);
    
    this->ruleMatrix = ruleMatrix;
    this->ruleGrpSID = ruleGrpSID;
    this->ruleNum = ruleNum;
    this->columnNum = columnNum;
    s.clear();
    currentField = 0;
    
    return 0;
}

INT32_T CSAlgo::reset()
{
    s.clear();
    currentField = 0;
    
    return 0;
}

/*
要求matchedRule为升序表。
*/
INT32_T CSAlgo::updateField(const UINT16_T fieldNo, std::vector<UINT16_T> * matchedRule)
{
    // assert(fieldNo == currentField);
    assert(matchedRule != NULL);
    
    UINT32_T siSize = s.size();
    
	std::sort(matchedRule->begin(), matchedRule->end());
	std::vector<UINT16_T>::iterator uIt = std::unique(matchedRule->begin(), matchedRule->end());
	// matchedRule->erase(uIt, matchedRule->end());
	/*
	if(uIt != matchedRule->end())
	{
		printf("uIt != matchedRule->end()\n");
	}
	*/
/*
#ifdef DEBUG
	fprintf(stdout, "Field: %u\n", currentField);
    std::vector<UINT16_T>::const_iterator vIt = matchedRule->begin();
    while(vIt != matchedRule->end())
    {
        fprintf(stdout, "Candidate %u\n", *vIt);
        vIt++;
    }
#endif
*/
    std::vector<UINT16_T>::iterator sIt = s.begin();
    while(sIt != s.end())
    {
        UINT32_T int8Num = (columnNum % 8 == 0) ? (columnNum / 8) : (columnNum / 8 + 1);
        if((ruleMatrix[(*sIt) * int8Num + (fieldNo / 8)] & (1 << (fieldNo % 8))) != 0)
        {
            if(std::binary_search(matchedRule->begin(), uIt, *sIt) == false)
            {
                sIt = s.erase(sIt);
            }
            else
            {
                sIt++;
            }
        }
        else
        {
            sIt++;
        }
    }
    
    UINT32_T biSize = 0;
    
    std::vector<UINT16_T>::const_iterator rIt = uIt;
    if(rIt != matchedRule->begin())
    {
        do
        {
            rIt--;
            if(*rIt >= ruleGrpSID[fieldNo])
            {
				/*
				if(find(s.begin(), s.end(), *rIt) != s.end())
				{
					printf("find(s.begin(), s.end(), *rIt) != s.end() > 0\n");
				}
				*/
                biSize++;
                s.push_back(*rIt);
            }
            else
            {
                break;
            }
        }while(rIt != matchedRule->begin());
    }
/*
#ifdef DEBUG
    std::vector<UINT16_T>::const_iterator it = s.begin();
    while(it != s.end())
    {
        fprintf(stdout, "Rule %u\n", *it);
        it++;
    }
    fprintf(stdout, "\n");
#endif
*/
    if(s.size() > maxSiSize)
    {
        maxSiSize = s.size();
    }
    
    UINT32_T aiSize = distance(matchedRule->begin(), uIt) - biSize;
    
    if(aiSize > maxAiSize)
    {
        maxAiSize = aiSize;
    }
    
    if(biSize > maxBiSize)
    {
        maxBiSize = biSize;
    }
    
    if(printcs->count > 0)
    {
        fprintf(stdout, "Si %u Ai %u Bi %u\n", siSize, aiSize, biSize);
    }

    currentField++;
    return 0;
}

const std::vector<UINT16_T> * CSAlgo::getAvailableRule()const
{
    return &s;
}
