#include "NetShield.h"
#include "DCERPCAnalyzer.h"

BOOL_T DCERPCAnalyzer::isInitialized = FALSE;

IntRangeStruct<UINT16_T> * DCERPCAnalyzer::bindRpcVerIntStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::bindPackedDRepIntStruct = NULL;
TrieStruct<UINT16_T> * DCERPCAnalyzer::uuidStringStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::versionIntStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::bindAckRpcVerIntStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::bindAckPackedDRepIntStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::requestRpcVerIntStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::requestPackedDRepIntStruct = NULL;
IntRangeStruct<UINT16_T> * DCERPCAnalyzer::opnumIntStruct = NULL;
vector<FieldSig> DCERPCAnalyzer::fieldSigVector;
DFAStruct<UINT16_T> * DCERPCAnalyzer::stubDFAStruct = NULL;

int charToInt(int ch)
{
    ch = tolower(ch);
    
    if(ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    else if(ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
    else
    {
        fprintf(stderr, "charToInt error!\n");
        exit(0);
    }
}

char * hexStringToString(const char * hexString)
{
    INT32_T length = strlen(hexString);
    
    unsigned char * result = new unsigned char[length/2];
    
    for(INT32_T i = 0; i < length/2; i++)
    {
        int high_char = charToInt(hexString[i * 2]);
        int low_char = charToInt(hexString[i * 2 + 1]);
                
        result[i] = high_char * 16 + low_char;
    }
    
    return (char *)result;
}

FieldFunc DCERPCAnalyzer::findFieldFunc(const char * funcName)
{
    if(strcmp(funcName, "REQUEST_stub_NetrWkstaUserEnum_server_name_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_NetrWkstaUserEnum_server_name_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_NetrAddAlternateComputerName_AlternateName_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_NetrAddAlternateComputerName_AlternateName_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_NetrJoinDomain2_DomainNameParam_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_NetrJoinDomain2_DomainNameParam_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_NetPathCanonicalize_path_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_NetPathCanonicalize_path_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_DnssrvQuery_paramb_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_DnssrvQuery_paramb_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_Spoolss_AddPrinterEx_server_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_Spoolss_AddPrinterEx_server_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_Tapsrv_ClientAttach_element_5_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_Tapsrv_ClientAttach_element_5_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_PNP_GetDeviceList_pszFilter_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_PNP_GetDeviceList_pszFilter_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_QMCreateObjectInternal_arg_2_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_QMCreateObjectInternal_arg_2_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_NetrSendMessage_Message_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_NetrSendMessage_Message_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_RemoteCreateInstance_after_orpcthis") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_RemoteCreateInstance_after_orpcthis;
    }
    else if(strcmp(funcName, "REQUEST_stub_RemoteActivation_pwszObjectName_actual_length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_RemoteActivation_pwszObjectName_actual_length;
    }
    else if(strcmp(funcName, "REQUEST_stub_Length") == 0)
    {
        return DCERPCAnalyzer::REQUEST_stub_Length;
    }
    else
    {
        return NULL;
    }
}

INT32_T DCERPCAnalyzer::loadConfig(TiXmlDocument & config)
{
    TiXmlHandle hConfig(&config);
    TiXmlHandle hRules = hConfig.FirstChild("NetShield").FirstChild("WINRPC").FirstChild("Signature").FirstChild("Rules");
    
    cout << "Compiling WINRPC signatures...\n";
    
    bindRpcVerIntStruct = new IntRangeStruct<UINT16_T>;
    verify(bindRpcVerIntStruct);
    
    bindPackedDRepIntStruct = new IntRangeStruct<UINT16_T>;
    verify(bindPackedDRepIntStruct);
    
    uuidStringStruct = new TrieStruct<UINT16_T>;
    verify(uuidStringStruct);
    
    versionIntStruct = new IntRangeStruct<UINT16_T>;
    verify(versionIntStruct);
    
    bindAckRpcVerIntStruct = new IntRangeStruct<UINT16_T>;
    verify(bindAckRpcVerIntStruct);
    
    bindAckPackedDRepIntStruct = new IntRangeStruct<UINT16_T>;
    verify(bindAckPackedDRepIntStruct);
    
    requestRpcVerIntStruct = new IntRangeStruct<UINT16_T>;
    verify(requestRpcVerIntStruct);
    
    requestPackedDRepIntStruct = new IntRangeStruct<UINT16_T>;
    verify(requestPackedDRepIntStruct);
    
    opnumIntStruct = new IntRangeStruct<UINT16_T>;
    verify(opnumIntStruct);
    
    fieldSigVector.push_back(FieldSig());
    
    stubDFAStruct = new DFAStruct<UINT16_T>;
    verify(stubDFAStruct);

	string combinedRegex;
    vector<DFAStruct<UINT16_T> *> subDFAVector;
    
    UINT32_T ruleID = 1;
    TiXmlElement * pRule = hRules.FirstChild("Rule").ToElement();
    while(pRule != NULL)
    {
		// fprintf(stderr, "Rule %d!\n", ruleID);
		
        TiXmlElement * pBindRpcVer = pRule->FirstChildElement("Bind_rpc_ver");
        const char * bindRpcVerStr = pBindRpcVer->Attribute("Str");
        verify(bindRpcVerStr);
        
        char * stop = NULL;
        bindRpcVerIntStruct->add((UINT32_T)strtol(bindRpcVerStr, &stop, 10), ruleID);
        
        TiXmlElement * pBindPackedDRep = pRule->FirstChildElement("Bind_packed_drep");
        const char * bindPackedDRep = pBindPackedDRep->Attribute("Hex");
        verify(bindPackedDRep);
        
        stop = NULL;
        bindPackedDRepIntStruct->add((UINT32_T)strtol(bindPackedDRep, &stop, 16), ruleID);
        
        TiXmlElement * pUuid = pRule->FirstChildElement("Uuid");
        const char * uuidHex = pUuid->Attribute("Hex");
        verify(uuidHex);
        
        TiXmlElement * pVersion = pRule->FirstChildElement("Version");
        const char * versionHex = pVersion->Attribute("Hex");
        verify(versionHex);
        
        TiXmlElement * pOpnum = pRule->FirstChildElement("Opnum");
        const char * opnumHex = pOpnum->Attribute("Hex");
        verify(opnumHex);
        
        TiXmlElement * pBindAckRpcVer = pRule->FirstChildElement("Bind_ack_rpc_ver");
        const char * bindAckRpcVerStr = pBindAckRpcVer->Attribute("Str");
        verify(bindAckRpcVerStr);
        
        stop = NULL;
        bindAckRpcVerIntStruct->add((UINT32_T)strtol(bindAckRpcVerStr, &stop, 10), ruleID);
        
        TiXmlElement * pBindAckPackedDRep = pRule->FirstChildElement("Bind_ack_packed_drep");
        const char * bindAckPackedDRep = pBindAckPackedDRep->Attribute("Hex");
        verify(bindAckPackedDRep);
        
        stop = NULL;
        bindAckPackedDRepIntStruct->add((UINT32_T)strtol(bindAckPackedDRep, &stop, 16), ruleID);
        
        TiXmlElement * pRequestRpcVer = pRule->FirstChildElement("Request_rpc_ver");
        const char * requestRpcVerStr = pRequestRpcVer->Attribute("Str");
        verify(requestRpcVerStr);
        
        stop = NULL;
        requestRpcVerIntStruct->add((UINT32_T)strtol(requestRpcVerStr, &stop, 10), ruleID);
        
        TiXmlElement * pRequestPackedDRep = pRule->FirstChildElement("Request_packed_drep");
        const char * requestPackedDRep = pRequestPackedDRep->Attribute("Hex");
        verify(requestPackedDRep);
        
        stop = NULL;
        requestPackedDRepIntStruct->add((UINT32_T)strtol(requestPackedDRep, &stop, 16), ruleID);
        
        TiXmlElement * pStub = pRule->FirstChildElement("Stub");
        const char * field = pStub->Attribute("Field");
        verify(field);
        
        INT32_T value;
        if(pStub->QueryIntAttribute("Value", &value) != TIXML_SUCCESS)
        {
            fprintf(stderr, "Error on reading \"Stub Value\"!\n");
        }
        
        FieldSig fieldSig;
        
        fieldSig.fieldFunc = findFieldFunc(field);
        if(fieldSig.fieldFunc == NULL)
        {
            fprintf(stderr, "Unknown field %s!\n", field);
            exit(0);
        }
        
        fieldSig.fieldValue = value;
        
        /*
        printf("%s\n", uuidHex);
        printf("%s\n", versionHex);
        printf("%s\n", opnumHex);
        printf("%s\n", field);
        printf("%d\n\n", value);
        */
        
        char * str = hexStringToString(uuidHex);
        uuidStringStruct->add(str, str + strlen(uuidHex)/2, ruleID);
		delete []str;
		
		stop = NULL;
		versionIntStruct->add((UINT32_T)strtol(versionHex, &stop, 16), ruleID);
		
		opnumIntStruct->add((UINT32_T)strtol(opnumHex, &stop, 16), ruleID);
		
		const char * regex = NULL;
		if((regex = pStub->Attribute("Regex")) != NULL)
        {
			if(combinedRegex.length() != 0)
			{
				combinedRegex += "|";
			}

			combinedRegex += regex;
	        
			DFAStruct<UINT16_T> * subDFA = new DFAStruct<UINT16_T>;
			subDFA->compile(regex);
			subDFA->annotate(ruleID, hasDollar(regex));

			subDFAVector.push_back(subDFA);
            
            fieldSig.hasRegex = true;
        }
        
        fieldSigVector.push_back(fieldSig);
                
        pRule = pRule->NextSiblingElement("Rule");
        ruleID++;
    }

	if(combinedRegex.length() > 0)
    {
        stubDFAStruct->compile(combinedRegex.c_str());
        vector<DFAStruct<UINT16_T> *>::iterator it = subDFAVector.begin();
        while(it != subDFAVector.end())
        {
            stubDFAStruct->annotate(**it);
            delete *it;
            it++;
        }
    }
    
    return 0;
}
