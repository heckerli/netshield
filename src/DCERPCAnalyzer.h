#ifndef _DCE_RPC_ANALYZER_H_
#define _DCE_RPC_ANALYZER_H_

#include <vector>
#include <map>
#include <algorithm>

#include "NetShield.h"
#include "Global.h"
#include "FlowAnalyzer.h"
#include "Util.h"
#include "CSAlgo.h"
#include "TrieMatcher.h"
#include "IntRangeMatcher.h"
#include "DFAMatcher.h"

#define MAKE_RPC_VERSION(major, minor) ((((major) & 0xff) << 24) | (((major) & 0xff00) << 8) | (((minor) & 0xff) << 8) | (((minor) & 0xff00) >> 8))

#define OUTPUT_WRAP(code) if(silent->count == 0) { code; }

void DCERPCAnalyzerSeqInit();
void DCERPCAnalyzerSeqMatch(UINT8_T bindRpcVer, UINT32_T bindPackedDrep, 
                 UINT8_T bindAckRpcVer, UINT32_T bindAckPackedDrep, 
                 UINT8_T requestRpcVer, UINT32_T requestPackedDrep, 
                 UINT8_T uuid[], UINT32_T version, UINT16_T opnum, 
                 UINT8_T * stub, UINT32_T stubLength);

class DCERPCAnalyzer;

class SyntaxID
{
public:
    UINT8_T uuid[16];
    UINT32_T version;
};

typedef UINT32_T (*FieldFunc)(UINT8_T * stub, UINT32_T stubLength);

class FieldSig
{
public:
    FieldSig()
    {
        fieldFunc = NULL;
        fieldValue = 0;
        
        hasRegex = false;
    }
    
    FieldFunc fieldFunc;
    UINT32_T fieldValue;
    
    BOOL_T hasRegex;
};

class DCERPCAnalyzer : public FlowAnalyzer
{
public:
    DCERPCAnalyzer(FlowHandler * flow, FlowDir dir)
    : FlowAnalyzer(flow, dir)
    {
        siSize = 0;
        aiSize = 0;
        biSize = 0;
        matchedNum = 0;
        
        dceRpcReassembly.reserve(8192);
        
        init();
        
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, bindRpcVerIntMatcher, bindRpcVerIntStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, bindPackedDRepIntMatcher, bindPackedDRepIntStruct);
        NEW_MATCHER(TrieMatcher<UINT16_T>, uuidStringMatcher, uuidStringStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, versionIntMatcher, versionIntStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, bindAckRpcVerIntMatcher, bindAckRpcVerIntStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, bindAckPackedDRepIntMatcher, bindAckPackedDRepIntStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, requestRpcVerIntMatcher, requestRpcVerIntStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, requestPackedDRepIntMatcher, requestPackedDRepIntStruct);
        NEW_MATCHER(IntRangeMatcher<UINT16_T>, opnumIntMatcher, opnumIntStruct);
        
        NEW_MATCHER(DFAMatcher<UINT16_T>, stubDFAMatcher, stubDFAStruct);
    }
    
    virtual ~DCERPCAnalyzer()
    {
    }
    
    static BOOL_T isInitialized;
    
    static INT32_T loadConfig(TiXmlDocument & config);
    
    static IntRangeStruct<UINT16_T> * bindRpcVerIntStruct;
    IntRangeMatcher<UINT16_T> * bindRpcVerIntMatcher;
    
    static IntRangeStruct<UINT16_T> * bindPackedDRepIntStruct;
    IntRangeMatcher<UINT16_T> * bindPackedDRepIntMatcher;
    
    static TrieStruct<UINT16_T> * uuidStringStruct;
    TrieMatcher<UINT16_T> * uuidStringMatcher;
    
    static IntRangeStruct<UINT16_T> * versionIntStruct;
    IntRangeMatcher<UINT16_T> * versionIntMatcher;
    
    static IntRangeStruct<UINT16_T> * bindAckRpcVerIntStruct;
    IntRangeMatcher<UINT16_T> * bindAckRpcVerIntMatcher;
    
    static IntRangeStruct<UINT16_T> * bindAckPackedDRepIntStruct;
    IntRangeMatcher<UINT16_T> * bindAckPackedDRepIntMatcher;
    
    static IntRangeStruct<UINT16_T> * requestRpcVerIntStruct;
    IntRangeMatcher<UINT16_T> * requestRpcVerIntMatcher;
    
    static IntRangeStruct<UINT16_T> * requestPackedDRepIntStruct;
    IntRangeMatcher<UINT16_T> * requestPackedDRepIntMatcher;
    
    static IntRangeStruct<UINT16_T> * opnumIntStruct;
    IntRangeMatcher<UINT16_T> * opnumIntMatcher;
    
    static vector<FieldSig> fieldSigVector;
    
    static DFAStruct<UINT16_T> * stubDFAStruct;
    DFAMatcher<UINT16_T> * stubDFAMatcher;
        
    static FieldFunc DCERPCAnalyzer::findFieldFunc(const char * funcName);
    
    static INT32_T init()
    {
        if(isInitialized == TRUE)
        {
            return 0;
        }
        
        isInitialized = TRUE;
        
        if(parseOnly->count == 0 && seqMatch->count == 0)
        {
            loadConfig(config);
        }
    
        return 0;
    }
    
    INT32_T resetState()
    {
        siSize = 0;
        aiSize = 0;
        biSize = 0;
        matchedNum = 0;

		return 0;
    }
    
    virtual INT32_T reset(FlowHandler * flow, FlowDir dir)
    {
        FlowAnalyzer::reset(flow, dir);
        
        resetState();
        
        return 0;
    }
    
    virtual INT32_T run()
    {
        // DEBUG_WRAP(DebugMessage("DCERPCAnalyzer: 0x%.8X, run()\n", this););
        verify(matched == false);
    
        while(1)
        {
            reset(flow, dir);
            
            parseDceRpcPdu(buffer);
            
            validPduNum += 1;
            
            if(matchedNum != 0 && matched == false)
            {
                matched = true;
                accMatchedFlowNum++;
            }
            
            // DEBUG_WRAP(DebugMessage("DCERPCAnalyzer: 0x%.8X, PDU length = %d\n", this, length););
        }
    
    	return 0;
    }
    
    UINT8_T bindRpcVer;
    UINT32_T bindPackedDrep;
    UINT8_T bindAckRpcVer;
    UINT32_T bindAckPackedDrep;

// protected:
    enum Endian
    {
        DCE_RPC_BIG_ENDIAN,
        DCE_RPC_LITTLE_ENDIAN,
    };
    enum DceRpcPduType
    {
        DCE_RPC_REQUEST,
        DCE_RPC_PING,
        DCE_RPC_RESPONSE,
        DCE_RPC_FAULT,
        DCE_RPC_WORKING,
        DCE_RPC_NOCALL,
        DCE_RPC_REJECT,
        DCE_RPC_ACK,
        DCE_RPC_CL_CANCEL,
        DCE_RPC_FACK,
        DCE_RPC_CANCEL_ACK,
        DCE_RPC_BIND,
        DCE_RPC_BIND_ACK,
        DCE_RPC_BIND_NAK,
        DCE_RPC_ALTER_CONTEXT,
        DCE_RPC_ALTER_CONTEXT_RESP,
        DCE_RPC_SHUTDOWN,
        DCE_RPC_CO_CANCEL,
        DCE_RPC_ORPHANED,
    };
    
    enum ItemState
    {
        ITEM_NULL,
        ITEM_FUNC,
        ITEM_NEXT,
    };
        
    std::vector<UINT8_T> dceRpcReassembly;
    std::map<UINT16_T, SyntaxID> mapCtxIDtoSyntaxID;
    UINT32_T siSize;
    UINT32_T aiSize;
    UINT32_T biSize;
    UINT32_T matchedNum;
    
    // type ORPCTHIS = record {
    //     version: COMVERSION; # COM version number
    //     flags: UINT32_T; # ORPCF flags for presence of other data
    //     reserved1: UINT32_T; # set to zero
    //     cid: GUID; # causality id of caller
    //     extensions_ptr: UINT32_T;
    //     extensions: case extensions_ptr of {
    //         0 -> extensions_empty: empty;
    //         default -> extensions_extent_array: ORPC_EXTENT_ARRAY; # Extensions.
    //     };
    // };
    
    inline static INT32_T parseOrpcthis(UINT8_T * data, UINT32_T dataLength)
    {
        UINT8_T * p = data;
        
        p += 28;
		if(p < data || p >= data + dataLength)
		{
			return dataLength;
		}
        
        UINT32_T extensionsPtr = *((UINT32_T*)p); // extensions_ptr: UINT32_T;
        p += 4;
		if(p < data || p >= data + dataLength)
		{
			return dataLength;
		}
        
        if(extensionsPtr != 0)
        {
            UINT32_T size;          // size: UINT32_T;
            size = *((UINT32_T*)p); // extensions_ptr: UINT32_T;
            p += 4;
			if(p < data || p >= data + dataLength)
			{
				return dataLength;
			}
            
            p += 4;
			if(p < data || p >= data + dataLength)
			{
				return dataLength;
			}
            
            for(UINT32_T i = 0; i < ((size + 1) &~ 1); i++)
            {
                p += 16;            // id: GUID;
				if(p < data || p >= data + dataLength)
				{
					return dataLength;
				}
                
                UINT32_T orpcExtentSize;
                orpcExtentSize = *((UINT32_T*)p);
                p += 4;
				if(p < data || p >= data + dataLength)
				{
				    return dataLength;
				}
                
                UINT32_T offset = (orpcExtentSize + 7) &~ 7;
                if(p + offset > data + dataLength)
                {
                    return p - data;
                }
                p += offset;
            }
        }
        
        return p - data;
    }
    
    inline static INT32_T parseCvstring(UINT8_T * data, UINT32_T dataLength)
    {
        UINT8_T * p = data;
        
        p += 8;
        
        UINT32_T actualCount = *((UINT32_T*)p);
        p += 4;
        
        p += actualCount * 2;
        
        return p - data;
    }
    
    inline BOOL_T matchString(UINT8_T * data, UINT8_T * dataEnd, TrieMatcher<UINT16_T> * stringMatcher, vector<UINT16_T> & result)
    {
        stringMatcher->matchFromScratch(data, dataEnd);
        
        TRIEState<UINT16_T> trieState;
        trieState = stringMatcher->getCurrentState();
        
        if(trieState.isFinal == true)
        {
            result.insert(result.end(), trieState.dataVector->begin(), trieState.dataVector->end());
            return true;
        }
        
        return false;
    }
    
    inline INT32_T matchIntEqual(UINT32_T data, IntRangeMatcher<UINT16_T> * intMatcher, vector<UINT16_T>::const_iterator * first, vector<UINT16_T>::const_iterator * last)
    {
        intMatcher->matchFromScratch(data);
        
        intMatcher->getEqCurrentState(first, last);
                
        return 0;
    }
    
    static void stubDFAMatchedCallback(const UINT16_T & ruleID, void * cbParam)
    {
        vector<UINT16_T> * matchedRuleVector = (vector<UINT16_T> *)cbParam;
        
        matchedRuleVector->push_back(ruleID);
    }
    
    inline void parseDceRpcBind(UINT8_T rpcVer, UINT32_T packedDRep, Buffer * buffer, UINT32_T length)
    {
        bindRpcVer = rpcVer;
        bindPackedDrep = packedDRep;
        
        UINT16_T maxXmitFrag;
        buffer->readUInt16(&maxXmitFrag);
        
        UINT16_T maxRecvFrag;
        buffer->readUInt16(&maxRecvFrag);
        
        UINT32_T assocGroupID;
        buffer->readUInt32(&assocGroupID);
        
        UINT8_T nContextElem = buffer->readUInt8();
        
        buffer->skip(3);

		mapCtxIDtoSyntaxID.clear();
        
        for(UINT8_T i = 0; i < nContextElem; i++)
        {
            UINT16_T ctxID;
            buffer->readUInt16(&ctxID);
            
            UINT8_T nTransferSyn = buffer->readUInt8();
            
            buffer->readUInt8();
            
            SyntaxID syntaxID;
            buffer->readArray(syntaxID.uuid, 16);
    
            buffer->readUInt32(&(syntaxID.version));
            
            mapCtxIDtoSyntaxID[ctxID] = syntaxID;
            
            for(UINT8_T j = 0; j < nTransferSyn; j++)
            {
                UINT8_T ifUuid[16];
                buffer->readArray(ifUuid, 16);
                
                UINT32_T ifVersion;
                buffer->readUInt32(&ifVersion);
            }
        }
    }
    
    inline void parseDceRpcBindAck(UINT8_T rpcVer, UINT32_T packedDRep, Buffer * buffer, UINT32_T length)
    {
		DCERPCAnalyzer * oppositeAnalyzer = (DCERPCAnalyzer *)flow->getConnection()->upFlow->analyzer;
		
		oppositeAnalyzer->bindAckRpcVer = rpcVer;
		oppositeAnalyzer->bindAckPackedDrep = packedDRep;
        
        INT32_T byteCountBegin = buffer->getByteCount();
        
        UINT16_T maxXmitFrag;
        buffer->readUInt16(&maxXmitFrag);
        
        UINT16_T maxRecvFrag;
        buffer->readUInt16(&maxRecvFrag);
        
        UINT32_T assocGroupID;
        buffer->readUInt32(&assocGroupID);
        
        UINT16_T portSpecLength;
        buffer->readUInt16(&portSpecLength);
        
        buffer->skip(portSpecLength);
        
        UINT8_T pad2Length = (4 - (portSpecLength + 2) % 4) % 4;
        buffer->skip(pad2Length);
        
        UINT8_T nResults = buffer->readUInt8();
        
        buffer->skip(3);
                
        for(UINT8_T i = 0; i < nResults; i++)
        {
            UINT16_T result;
            buffer->readUInt16(&result);
            
            UINT16_T reason;
            buffer->readUInt16(&reason);
            
            UINT8_T ifUuid[16];
            buffer->readArray(ifUuid, 16);
    
            UINT32_T ifVersion;
            buffer->readUInt32(&ifVersion);
        }
        
        UINT32_T currentLength = buffer->getByteCount() - byteCountBegin;
        buffer->skip(length - currentLength);
    }
    
    inline void parseDceRpcRequest(UINT8_T rpcVer, UINT32_T packedDRep, Buffer * buffer, UINT32_T length)
    {
        UINT32_T allocHint;
        buffer->readUInt32(&allocHint);
        
        UINT16_T ctxID;
        buffer->readUInt16(&ctxID);
        
        UINT16_T opnum;
        buffer->readUInt16(&opnum);
        
        UINT8_T * stub = buffer->getCurrentDataPtr();
        UINT32_T stubLength = buffer->getLength();
        if(stubLength > length - 8)
        {
            stubLength = length - 8;
        }
        
        if(parseOnly->count == 0 && mapCtxIDtoSyntaxID.find(ctxID) != mapCtxIDtoSyntaxID.end())
        {
            SyntaxID & syntaxID = mapCtxIDtoSyntaxID[ctxID];

            /*
			Connection * conn = flow->getConnection();
            
            if(reassembled->count == 1)
            {
                fprintf(stdout, "Connection %u: \n", conn->tuple5.origIP);
            }
            else
            {s
                fprintf(stdout, "Connection %s: \n", conn->tuple5.toString().c_str());
            }
            */
            
			if(seqMatch->count > 0)
            {
                DCERPCAnalyzerSeqMatch(bindRpcVer, bindPackedDrep, bindAckRpcVer, bindAckPackedDrep, rpcVer, packedDRep, 
                    syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
            }
            else
            {
				Connection * conn = flow->getConnection();

                vector<UINT16_T> result;
                
                if(matchString(syntaxID.uuid, syntaxID.uuid + 16, uuidStringMatcher, result) == false)
                {
                    return;
                }
                
                if(matchIntEqualCS(syntaxID.version, versionIntMatcher, result) == false)
                {
                    return;
                }
                
                if(matchIntEqualCS(opnum, opnumIntMatcher, result) == false)
                {
                    return;
                }
                
                if(matchIntEqualCS(bindRpcVer, bindRpcVerIntMatcher, result) == false)
                {
                    return;
                }
                
    			if(matchIntEqualCS(bindPackedDrep, bindPackedDRepIntMatcher, result) == false)
                {
                    return;
                }
    			    
    			if(matchIntEqualCS(bindAckRpcVer, bindAckRpcVerIntMatcher, result) == false)
                {
                    return;
                }
                
    			if(matchIntEqualCS(bindAckPackedDrep, bindAckPackedDRepIntMatcher, result) == false)
                {
                    return;
                }
    			    
                if(matchIntEqualCS(rpcVer, requestRpcVerIntMatcher, result) == false)
                {
                    return;
                }
                
                if(matchIntEqualCS(packedDRep, requestPackedDRepIntMatcher, result) == false)
                {
                    return;
                }
                
                if(printcs->count > 0)
                {
                    siSize = result.size();
                    aiSize = 0;
                    
                    if(siSize > maxSiSize)
                    {
                        maxSiSize = siSize;
                    }
                    
                    if(reassembled->count == 1)
                    {
                        fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                    }
                    else
                    {
                        fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                    }
                    
                    fprintf(stdout, "Si %u Ai %u Bi 0\n", siSize, aiSize);
                }
                
                bool hasStubRegex = false;
                
                std::vector<UINT16_T>::const_iterator it = result.begin();
                while(it != result.end())
                {
                    if(fieldSigVector[*it].fieldFunc(stub, stubLength) <= fieldSigVector[*it].fieldValue)
                    {
                		it = result.erase(it);
                		continue;
                    }
                    
                    if(fieldSigVector[*it].hasRegex == true)
                    {
                        hasStubRegex = true;
                    }
                    
                    it++;
                }
                
                if(hasStubRegex == true)
                {
                    vector<UINT16_T> stubDFAMatchedRuleVector;
                    stubDFAMatcher->reset();
                    stubDFAMatcher->match(stub, stub + stubLength, stubDFAMatchedCallback, &stubDFAMatchedRuleVector);
                    stubDFAMatcher->getCurrentState(stubDFAMatchedCallback, &stubDFAMatchedRuleVector);
                    
                    it = result.begin();
                    while(it != result.end())
                    {
                        if(fieldSigVector[*it].hasRegex == true)
                        {
                            if(find(stubDFAMatchedRuleVector.begin(), stubDFAMatchedRuleVector.end(), *it) == stubDFAMatchedRuleVector.end())
                            {
                			    it = result.erase(it);
                			    continue;
                			}
                        }
                        
                        it++;
                    }
                }
                
                if(result.size() > 0)
                {
                    if(matched == false)
                    {
                        accMatchedFlowNum++;
                    }
                    
                    matched = true;
                }
                
                if(printcs->count > 0)
                {
                    siSize = result.size();
                    aiSize = 0;
                    
                    if(siSize > maxSiSize)
                    {
                        maxSiSize = siSize;
                    }
                    
                    if(reassembled->count == 1)
                    {
                        fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                    }
                    else
                    {
                        fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                    }
                    
                    fprintf(stdout, "Si %u Ai %u Bi 0\n\n", siSize, aiSize);
                }
                
                // if(silent->count == 0)
                {
                    it = result.begin();
                    while(it != result.end())
                    {
                        if(silent->count == 0)
                        {
                            if(reassembled->count == 1)
                            {
                                fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                            }
                            else
                            {
                                fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                            }
                            
                            fprintf(stdout, "Rule %d matched!\n", *it);
                        }
                        
                        if(ruleMap.find(*it) == ruleMap.end())
                        {
                            ruleMap[*it] = 1;
                        }
                        else
                        {
                            ruleMap[*it] += 1;
                        }
                        
                        it++;
                    }
                }
            }
        }
        
        buffer->skip(length - 8);
    }
    
    inline void parseDceRpcResponse(UINT8_T rpcVer, UINT32_T packedDRep, Buffer * buffer, UINT32_T length)
    {
        UINT32_T allocHint;
        buffer->readUInt32(&allocHint);
        
        UINT16_T ctxID;
        buffer->readUInt16(&ctxID);
        
        UINT8_T cancelCount = buffer->readUInt8();
        
        buffer->readUInt8();
        
        buffer->skip(length - 8); // stub
    }
    
    inline void parseDceRpcFault(UINT8_T rpcVer, UINT32_T packedDRep, Buffer * buffer, UINT32_T length)
    {
        UINT32_T allocHint;
        buffer->readUInt32(&allocHint);
        
        UINT16_T ctxID;
        buffer->readUInt16(&ctxID);
        
        UINT8_T cancelCount = buffer->readUInt8();
        buffer->readUInt8();
        UINT32_T status;
        buffer->readUInt32(&status);
        
        buffer->skip(4);
    }
    
    inline void parseDceRpcPdu(Buffer * buffer)
    {                        
        UINT8_T rpcVer = buffer->readUInt8();
        
        /*
        if(rpcVer != 5)
        {
            ReportError(flow->getConnection(), "RPC version is not 5!\n");
        }
        */
        
        UINT8_T rpcVerMinor = buffer->readUInt8();
        
        UINT8_T ptype = buffer->readUInt8();
        
        UINT8_T pfcFlags = buffer->readUInt8();
        BOOL_T firstFrag = ((pfcFlags & 0x01) != 0);
        BOOL_T lastFrag = ((pfcFlags & 0x02) != 0);
        
        UINT32_T packedDrep;
		buffer->readUInt32(&packedDrep);
        
        UINT8_T packedDrepIntChar = packedDrep & 0xff;
        Endian byteOrder = (packedDrepIntChar >> 4) ? DCE_RPC_LITTLE_ENDIAN : DCE_RPC_BIG_ENDIAN;
        
        UINT8_T floatSpec = (packedDrep >> 8) & 0xff;
        
        UINT16_T fragLength;
        buffer->readUInt16(&fragLength);
        
        if(byteOrder == DCE_RPC_BIG_ENDIAN)
        {
            fragLength = ntohs(fragLength);
        }
        
        UINT16_T authLength;
        buffer->readUInt16(&authLength);
        
        if(byteOrder == DCE_RPC_BIG_ENDIAN)
        {
            authLength = ntohs(authLength);
        }
        
        UINT32_T callID;
        buffer->readUInt32(&callID);
        
        UINT32_T bodyLength = fragLength - 16 - authLength;
        
        if(firstFrag == TRUE && lastFrag == TRUE)
        {
            switch(ptype)
            {
            case DCE_RPC_BIND:
                parseDceRpcBind(rpcVer, packedDrep, buffer, bodyLength);
                break;
            case DCE_RPC_BIND_ACK:
                parseDceRpcBindAck(rpcVer, packedDrep, buffer, bodyLength);
                break;
            case DCE_RPC_REQUEST:
                parseDceRpcRequest(rpcVer, packedDrep, buffer, bodyLength);
                break;
            case DCE_RPC_RESPONSE:
                parseDceRpcResponse(rpcVer, packedDrep, buffer, bodyLength);
                break;
            case DCE_RPC_FAULT:
                parseDceRpcFault(rpcVer, packedDrep, buffer, bodyLength);
                break;
            default:
                buffer->skip(bodyLength - 8);
                break;
            }
        }
        else if(firstFrag == TRUE)
        {
            dceRpcReassembly.clear();
            for(UINT32_T i = 0; i < bodyLength; i++)
            {
                dceRpcReassembly.push_back(buffer->readUInt8());
            }
        }
        else if(lastFrag == TRUE)
        {
            for(UINT32_T i = 0; i < bodyLength; i++)
            {
                dceRpcReassembly.push_back(buffer->readUInt8());
            }
            
            UINT32_T dataLength = dceRpcReassembly.size();
            UINT8_T * data = new UINT8_T[dataLength];
            for(UINT32_T j = 0; j < dataLength; j++)
            {
                data[j] = dceRpcReassembly[j];
            }
            Buffer dceRpcReassemblyBuffer;
            dceRpcReassemblyBuffer.newData(data, dataLength);
            
            switch(ptype)
            {
            case DCE_RPC_BIND:
                parseDceRpcBind(rpcVer, packedDrep, &dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_BIND_ACK:
                parseDceRpcBindAck(rpcVer, packedDrep, &dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_REQUEST:
                parseDceRpcRequest(rpcVer, packedDrep, &dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_RESPONSE:
                parseDceRpcResponse(rpcVer, packedDrep, &dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_FAULT:
                parseDceRpcFault(rpcVer, packedDrep, &dceRpcReassemblyBuffer, dataLength);
                break;
            default:
                break;
            }
            
            delete []data;
            dceRpcReassembly.clear();
        }
        else
        {
            for(UINT32_T i = 0; i < bodyLength; i++)
            {
                dceRpcReassembly.push_back(buffer->readUInt8());
            }
        }
        
        buffer->skip(authLength);
    }
    
    static UINT32_T cvsStringActualCount(UINT8_T * data, UINT32_T dataLength)
    {
        if(dataLength < 16)
        {
            return 0;
        }
        
        UINT8_T * p = data;
    
        p += 4;
        
        p += 4; // max_count: uint32;
        p += 4; // offset: uint32;
        UINT32_T actual_length; // actual_length: uint32;
        actual_length = *((UINT32_T*)p);
        
        return actual_length;
    }
    
    static UINT32_T stubSecondCvsStringActualCount(UINT8_T * stub, UINT32_T stubLength)
    {
        UINT8_T * p = stub;
    
        p += 4;
        
        p += parseCvstring(p, stubLength - (p - stub));
        
        return cvsStringActualCount(p, stubLength - (p - stub));
    }
    
    static UINT32_T REQUEST_stub_NetrWkstaUserEnum_server_name_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return cvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_NetrAddAlternateComputerName_AlternateName_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return stubSecondCvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_NetrJoinDomain2_DomainNameParam_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return stubSecondCvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_NetPathCanonicalize_path_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return stubSecondCvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_DnssrvQuery_paramb_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return stubSecondCvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_Spoolss_AddPrinterEx_server_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return cvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_Tapsrv_ClientAttach_element_5_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        stub += 4;
        stubLength -= 4;
        return stubSecondCvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_PNP_GetDeviceList_pszFilter_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        return cvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_QMCreateObjectInternal_arg_2_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        stub += 4;
        stubLength -= 4;
        return stubSecondCvsStringActualCount(stub, stubLength);
    }
    
    static UINT32_T REQUEST_stub_NetrSendMessage_Message_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        UINT8_T * p = stub;
        
        p += parseCvstring(p, stubLength - (p - stub));
        p += parseCvstring(p, stubLength - (p - stub));
        
        p += 4; // max_count: uint32;
        p += 4; // offset: uint32;
        UINT32_T actual_length; // actual_length: uint32;
        actual_length = *((UINT32_T*)p);
        
        return actual_length;
    }
    
    static UINT32_T REQUEST_stub_RemoteCreateInstance_after_orpcthis(UINT8_T * stub, UINT32_T stubLength)
    {
        UINT8_T * p = stub;
        
        p += parseOrpcthis(p, stubLength);
        
        return (stubLength - (p - stub));
    }
    
    static UINT32_T REQUEST_stub_RemoteActivation_pwszObjectName_actual_length(UINT8_T * stub, UINT32_T stubLength)
    {
        UINT8_T * p = stub;
                
        p += parseOrpcthis(p, stubLength);
        p += 16;
        p += 4;
        
        p += 4; // max_count: UINT32_T;
        p += 4; // offset: UINT32_T;
        
		if(p < stub || p >= stub + stubLength)
		{
			return 0;
		}
		
        UINT32_T actual_length; // actual_length: UINT32_T;
        actual_length = *((UINT32_T*)p);
                
        return actual_length;
    }
    
    static UINT32_T REQUEST_stub_Length(UINT8_T * stub, UINT32_T stubLength)
    {
        return stubLength;
    }
    
    BOOL_T matchIntEqualCS(UINT32_T data, IntRangeMatcher<UINT16_T> * intMatcher, vector<UINT16_T> & result)
    {
		Connection * conn = flow->getConnection();

        vector<UINT16_T>::const_iterator first, last;
        
        matchIntEqual(data, intMatcher, &first, &last);
        if(first == last)
        {
            return false;
        }
        
        if(printcs->count > 0)
        {
            siSize = result.size();
            
            if(siSize > maxSiSize)
            {
                maxSiSize = siSize;
            }
            
            if(reassembled->count == 1)
            {
                fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
            }
            else
            {
                fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
            }
        
            fprintf(stdout, "Si %u Ai %u Bi 0\n", siSize, aiSize);
        }
        
        vector<UINT16_T> r(min(result.size(), distance(first, last)), 0);
        
        vector<UINT16_T>::iterator rEnd = set_intersection(result.begin(), result.end(),
                                                           first, last, r.begin());
        
        if(r.begin() == rEnd)
        {
            return false;
        }
        
        result.clear();
        result.insert(result.begin(), r.begin(), rEnd);
        
        return true;
    }
};

#endif
