#ifndef _DCE_RPC_ANALYZER_H_
#define _DCE_RPC_ANALYZER_H_

#include <vector>
#include <map>
#include <algorithm>

#include "NetShield.h"
#include "Global.h"
#include "FlowAnalyzer.h"
#include "Util.h"

#define MAKE_RPC_VERSION(major, minor) ((((major) & 0xff) << 24) | (((major) & 0xff00) << 8) | (((minor) & 0xff) << 8) | (((minor) & 0xff00) >> 8))

#define OUTPUT_WRAP(code) if(silent->count == 0) { code; }

class DCERPCAnalyzer;

typedef BOOL_T (DCERPCAnalyzer::*Matching_Func_Type)(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * p_data_begin, UINT32_T data_length);

class SyntaxID
{
public:
    UINT8_T uuid[16];
    UINT32_T version;
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
    }
    
    virtual ~DCERPCAnalyzer()
    {
    }
    
    static INT32_T init()
    {
        if(opnumVector.size() == 0)
        {
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x05);
            opnumVector.push_back(0x13);
            opnumVector.push_back(0x26);
            opnumVector.push_back(0x0f);
            opnumVector.push_back(0x24);
            opnumVector.push_back(0x02);
            opnumVector.push_back(0x1b);
            opnumVector.push_back(0x16);
            opnumVector.push_back(0x1f);
            opnumVector.push_back(0x28);
            opnumVector.push_back(0x01);
            opnumVector.push_back(0x0a);
            opnumVector.push_back(0x0c);
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x07);
            opnumVector.push_back(0x01);
            opnumVector.push_back(0x46);
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x36);
            opnumVector.push_back(0x0a);
            opnumVector.push_back(0x09);
            opnumVector.push_back(0x06);
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x0c);
            opnumVector.push_back(0x09);
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x04);
            opnumVector.push_back(0x03);
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x00);
            opnumVector.push_back(0x02);
            opnumVector.push_back(0x07);
            opnumVector.push_back(0x2d);
            opnumVector.push_back(0x2b);
            opnumVector.push_back(0x25);
            opnumVector.push_back(0xbf);
            opnumVector.push_back(0xff);
            opnumVector.push_back(0x01);
            
            std::sort(opnumVector.begin(), opnumVector.end());
            
            array[0][0x14].state = ITEM_FUNC;  array[0][0x14].func = &Is_NsiC_nsi_binding_lookup_begin_Exploit;
            array[0][0x20].state = ITEM_NEXT;  array[0][0x20].next = 1;
            array[0][0x30].state = ITEM_FUNC;  array[0][0x30].func = &Is_Qmcomm_QMDeleteObject_Exploit;
            array[0][0x36].state = ITEM_FUNC;  array[0][0x36].func = &Is_Rras_RasRpcSetUserPreferences_Exploit;
            array[0][0x40].state = ITEM_FUNC;  array[0][0x40].func = &Is_Ntsvcs_PNP_QueryResConfList_Exploit;
            array[0][0x60].state = ITEM_FUNC;  array[0][0x60].func = &Is_Irot_IrotIsRunning_Exploit;
            array[0][0x6a].state = ITEM_FUNC;  array[0][0x6a].func = &Is_Lsarpc_DsRoleUpgradeDownlevelServer_Exploit;
            array[0][0x78].state = ITEM_NEXT;  array[0][0x78].next = 2;
            array[0][0x81].state = ITEM_FUNC;  array[0][0x81].func = &Is_MS_Svcctl_ChangeServiceConfig2A_Exploit;
            array[0][0x87].state = ITEM_FUNC;  array[0][0x87].func = &Is_Davclntrpc_DavrCreateConnection_Exploit;
            array[0][0x88].state = ITEM_FUNC;  array[0][0x88].func = &Is_Trend_Micro_25395_Exploit;
            array[0][0x90].state = ITEM_FUNC;  array[0][0x90].func = &Is_CA_24947_Exploit;
            array[0][0x98].state = ITEM_FUNC;  array[0][0x98].func = &Is_Wkssvc_NetWkstaEnumUsers_Exploit;
            array[0][0xa0].state = ITEM_FUNC;  array[0][0xa0].func = &Is_ISystemActivator_RemoteCreateInstance_Exploit;
            array[0][0xa4].state = ITEM_FUNC;  array[0][0xa4].func = &Is_Dnsserver_DnssrvQuery_Exploit;
            array[0][0xb8].state = ITEM_FUNC;  array[0][0xb8].func = &Is_IRemoteActivation_RemoteActivation_Exploit;
            array[0][0xc8].state = ITEM_FUNC;  array[0][0xc8].func = &Is_Srvsvc_NetPathCanonicalize_Exploit;
            array[0][0xd0].state = ITEM_NEXT;  array[0][0xd0].next = 3;
            array[0][0xe0].state = ITEM_NEXT;  array[0][0xe0].next = 4;
            array[0][0xf0].state = ITEM_NEXT;  array[0][0xf0].next = 5;
            array[0][0xf8].state = ITEM_FUNC;  array[0][0xf8].func = &Is_Msgsvcsend_NetrSendMessage_Exploit;
            
            array[1][0x32].state = ITEM_FUNC;  array[1][0x32].func = &Is_Nddeapi_NDdeSetTrustedShareW_Exploit;
            array[1][0x65].state = ITEM_FUNC;  array[1][0x65].func = &Is_Tapsrv_ClientAttach_Exploit;
            
            array[2][0x56].state = ITEM_FUNC;  array[2][0x56].func = &Is_Spoolss_AddPrinterEx_Exploit;
            array[2][0x57].state = ITEM_FUNC;  array[2][0x57].func = &Is_Samba_23973_or_24197_Exploit;
            
            array[3][0x1f].state = ITEM_FUNC;  array[3][0x1f].func = &Is_Veritas_14020_Exploit;
            array[3][0x4c].state = ITEM_FUNC;  array[3][0x4c].func = &Is_Llslicense_LlsrLicenseRequestW_Exploit;
            
            array[4][0x0c].state = ITEM_FUNC;  array[4][0x0c].func = &Is_IXnRemote_BuildContextW_Exploit;
            array[4][0x42].state = ITEM_FUNC;  array[4][0x42].func = &Is_Samba_24198_Exploit;
            array[4][0x5e].state = ITEM_FUNC;  array[4][0x5e].func = &Is_CA_20365_Exploit;
            
            array[5][0x3d].state = ITEM_FUNC;  array[5][0x3d].func = &Is_CA_22006_Exploit;
            array[5][0x6b].state = ITEM_FUNC;  array[5][0x6b].func = &Is_CA_21221_Exploit;
        }
        
        return 0;
    }
    
    virtual INT32_T reset(FlowHandler * flow, FlowDir dir)
    {
        FlowAnalyzer::reset(flow, dir);
        
        siSize = 0;
        aiSize = 0;
        biSize = 0;
        matchedNum = 0;
        
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

protected:
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
    
    class Item
    {
    public:
        Item()
        {
            state = ITEM_NULL;
            func = NULL;
            next = 0;
        }
        
        ItemState state;
        Matching_Func_Type func;
        unsigned int next;
    };
    
    static Item array[6][256];
    
    static std::vector<UINT16_T> opnumVector;
    
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
    
    inline INT32_T parseOrpcthis(UINT8_T * data, UINT32_T dataLength)
    {
        UINT8_T * p = data;
        
        p += 28;
		if(p >= data + dataLength)
		{
			return dataLength;
		}
        
        UINT32_T extensionsPtr = *((UINT32_T*)p); // extensions_ptr: UINT32_T;
        p += 4;
		if(p >= data + dataLength)
		{
			return dataLength;
		}
        
        if(extensionsPtr != 0)
        {
            UINT32_T size;          // size: UINT32_T;
            size = *((UINT32_T*)p); // extensions_ptr: UINT32_T;
            p += 4;
			if(p > data + dataLength)
			{
				return dataLength;
			}
            
            p += 4;
			if(p >= data + dataLength)
			{
				return dataLength;
			}
            
            for(UINT32_T i = 0; i < ((size + 1) &~ 1); i++)
            {
                p += 16;            // id: GUID;
				if(p >= data + dataLength)
				{
					return dataLength;
				}
                
                UINT32_T orpcExtentSize;
                orpcExtentSize = *((UINT32_T*)p);
                p += 4;
				if(p >= data + dataLength)
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
    
    inline INT32_T parseCvstring(UINT8_T * data, UINT32_T dataLength)
    {
        UINT8_T * p = data;
        
        p += 8;
        
        UINT32_T actualCount = *((UINT32_T*)p);
        p += 4;
        
        p += actualCount * 2;
        
        return p - data;
    }
    
    BOOL_T Is_Trend_Micro_25395_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x88, 0x88, 0x28, 0x25, 0x5b, 0xbd, 0xd1, 0x11, 0x9d, 0x53, 0x00, 0x80, 0xc8, 0x3a, 0x5c, 0x2c};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Trend_Micro_25395 exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }
    
    BOOL_T Is_Samba_24198_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xe0, 0x42, 0xc7, 0x4f, 0x10, 0x4a, 0xcf, 0x11, 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73};
        const UINT32_T VERSION = MAKE_RPC_VERSION(3, 0);
        const UINT16_T OPNUM = 0x05;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Samba_24198 exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Samba_23973_or_24197_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID_15[] = {0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89};
        const UINT8_T UUID_23973 = 0xab;
        const UINT8_T UUID_24197 = 0xac;
        const UINT32_T VERSION = MAKE_RPC_VERSION(0, 0);
        const UINT16_T OPNUM_23973 = 0x13;
        const UINT16_T OPNUM_24197 = 0x26;
        const UINT16_T OPNUM_24195 = 0x0f;
    
        for(int i = 0; i < 15; i++)
        {
            if(uuid[i] != UUID_15[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        if(uuid[15] == UUID_23973)
        {
            siSize += 2;
            
            if(opnum == OPNUM_23973 && dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Samba_23973 exploit.\n"););
                return TRUE;
            }
            else if(opnum == OPNUM_24195 && dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Samba_24195 exploit.\n"););
                return TRUE;
            }
        }
        else if(uuid[15] == UUID_24197)
        {
            siSize += 1;
            
            if(opnum == OPNUM_24197 && dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Samba_24197 exploit.\n"););
                return TRUE;
            }
        }
        else
        {
            return FALSE;
        }
    
    	return FALSE;
    }

    BOOL_T Is_MS_Svcctl_ChangeServiceConfig2A_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03};
        const UINT32_T VERSION = MAKE_RPC_VERSION(2, 0);
        const UINT16_T OPNUM = 0x24;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "MS_Svcctl_ChangeServiceConfig2A exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }
    
    BOOL_T Is_Wkssvc_NetWkstaEnumUsers_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36, 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_6723 = 0x02;
        const UINT16_T OPNUM_9011 = 0x1b;
        const UINT16_T OPNUM_20985 = 0x16;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 3;
        
        if(opnum == OPNUM_6723)
        {
            UINT8_T * p = data;
        
            p += 4;
            
            p += 4; // max_count: UINT32_T;
            p += 4; // offset: UINT32_T;
            UINT32_T actual_count; // actual_count: UINT32_T;
            actual_count = *((UINT32_T*)p);
            p += 4;
            
            if(actual_count > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Wkssvc_NetWkstaEnumUsers exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_9011)
        {
            UINT8_T * p = data;
        
            p += 4;
            
            p += parseCvstring(p, dataLength - (p - data));
            
            p += 4;
            
            p += 4; // max_count: UINT32_T;
            p += 4; // offset: UINT32_T;
            UINT32_T actual_count; // actual_count: UINT32_T;
            actual_count = *((UINT32_T*)p);
            p += 4;
            
            if(actual_count > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Wkssvc_NetrAddAlternateComputerName exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_20985)
        {
            UINT8_T * p = data;
        
            p += 4;
            
            p += parseCvstring(p, dataLength - (p - data));
            
            p += 4;
            
            p += 4; // max_count: UINT32_T;
            p += 4; // offset: UINT32_T;
            UINT32_T actual_count; // actual_count: UINT32_T;
            actual_count = *((UINT32_T*)p);
            p += 4;
            
            if(actual_count > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Wkssvc_NetrJoinDomain2 exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }

    BOOL_T Is_Srvsvc_NetPathCanonicalize_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88};
        const UINT32_T VERSION = MAKE_RPC_VERSION(3, 0);
        const UINT16_T OPNUM_19409 = 0x1f;
        const UINT16_T OPNUM_24196 = 0x28;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_19409)
        {
            UINT8_T * p = data;
        
            p += 4;
            
            p += parseCvstring(p, dataLength - (p - data));
            
            p += 2;
            
            p += 4; // max_count: UINT32_T;
            p += 4; // offset: UINT32_T;
            UINT32_T actual_count; // actual_count: UINT32_T;
            actual_count = *((UINT32_T*)p);
            p += 4;
            
            if(actual_count > 0x200)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Srvsvc_NetPathCanonicalize exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_24196)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Samba_24196 exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }

    BOOL_T Is_Dnsserver_DnssrvQuery_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xa4, 0xc2, 0xab, 0x50, 0x4d, 0x57, 0xb3, 0x40, 0x9d, 0x66, 0xee, 0x4f, 0xd5, 0xfb, 0xa0, 0x76};
        const UINT32_T VERSION = MAKE_RPC_VERSION(5, 0);
        const UINT16_T OPNUM = 0x01;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        UINT8_T * p = data;
        
        p += 4;
        
        p += parseCvstring(p, dataLength - (p - data));
        
        p += 4;
        
        p += 4; // max_count: UINT32_T;
        p += 4; // offset: UINT32_T;
        UINT32_T actual_count; // actual_count: UINT32_T;
        actual_count = *((UINT32_T*)p);
        p += 4;
        
        if(actual_count > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Dnsserver_DnssrvQuery exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Rras_RasRpcSetUserPreferences_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x36, 0x00, 0x61, 0x20, 0x22, 0xfa, 0xcf, 0x11, 0x98, 0x23, 0x00, 0xa0, 0xc9, 0x11, 0xe5, 0xdf};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_18325 = 0x0a;
        const UINT16_T OPNUM_18358 = 0x0c;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_18325)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Rras_RasRpcSetUserPreferences exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_18358)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Rras_RasRpcSubmitRequest exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }
    
    BOOL_T Is_Davclntrpc_DavrCreateConnection_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x87, 0x76, 0xcb, 0xc8, 0xd3, 0xe6, 0xd2, 0x11, 0xa9, 0x58, 0x00, 0xc0, 0x4f, 0x68, 0x2e, 0x16};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Davclntrpc_DavrCreateConnection exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_IXnRemote_BuildContextW_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xe0, 0x0c, 0x6b, 0x90, 0x0b, 0xc7, 0x67, 0x10, 0xb3, 0x17, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_15056 = 0x07;
        const UINT16_T OPNUM_17905 = 0x01;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_15056)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "IXnRemote_BuildContextW exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_17905)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "IXnRemote_BuildContext exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }
    
    BOOL_T Is_Spoolss_AddPrinterEx_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x46;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        UINT8_T * p = data;
        
        p += 4;
        
        p += 4; // max_count: UINT32_T;
        p += 4; // offset: UINT32_T;
        UINT32_T actual_count; // actual_count: UINT32_T;
        actual_count = *((UINT32_T*)p);
        p += 4;
        
        if(actual_count > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Spoolss_AddPrinterEx exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Tapsrv_ClientAttach_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x20, 0x65, 0x5f, 0x2f, 0x46, 0xca, 0x67, 0x10, 0xb3, 0x19, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        UINT8_T * p = data;
        
        p += 8;
        
        p += parseCvstring(p, dataLength - (p - data));
        
        p += 4;
        
        p += 4; // max_count: UINT32_T;
        p += 4; // offset: UINT32_T;
        UINT32_T actual_count; // actual_count: UINT32_T;
        actual_count = *((UINT32_T*)p);
        p += 4;
        
        if(actual_count > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Tapsrv_ClientAttach exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Ntsvcs_PNP_QueryResConfList_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x40, 0x4e, 0x9f, 0x8d, 0x3d, 0xa0, 0xce, 0x11, 0x8f, 0x69, 0x08, 0x00, 0x3e, 0x30, 0x05, 0x1b};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_14513 = 0x36;
        const UINT16_T OPNUM_15065 = 0x0a;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_14513)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Ntsvcs_PNP_QueryResConfList exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_15065)
        {
            UINT8_T * p = data;
        
            p += 4;
            
            p += 4; // max_count: UINT32_T;
            p += 4; // offset: UINT32_T;
            UINT32_T actual_count; // actual_count: UINT32_T;
            actual_count = *((UINT32_T*)p);
            p += 4;
            
            if(actual_count > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Ntsvcs_PNP_GetDeviceList exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }

    BOOL_T Is_Qmcomm_QMDeleteObject_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x30, 0xa0, 0xb3, 0xfd, 0x5f, 0x06, 0xd1, 0x11, 0xbb, 0x9b, 0x00, 0xa0, 0x24, 0xea, 0x55, 0x25};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_13112 = 0x09;
        const UINT16_T OPNUM_26797 = 0x06;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_13112)
        {
            if(dataLength > 0x200)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Qmcomm_QMDeleteObject exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_26797)
        {
            UINT8_T * p = data;
        
            UINT32_T arg_1;
            arg_1 = *((UINT32_T*)p);
            p += 4;
            
            p += 4;
            
            p += 4; // max_count: UINT32_T;
            p += 4; // offset: UINT32_T;
            UINT32_T actual_count; // actual_count: UINT32_T;
            actual_count = *((UINT32_T*)p);
            p += 4;
            
            if(arg_1 == 0x00000001 && actual_count > 0x200)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "Qmcomm_QMCreateObjectInternal exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }

    BOOL_T Is_Llslicense_LlsrLicenseRequestW_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xd0, 0x4c, 0x67, 0x57, 0x00, 0x52, 0xce, 0x11, 0xa8, 0x97, 0x08, 0x00, 0x2b, 0x2e, 0x9c, 0x6d};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Llslicense_LlsrLicenseRequestW exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Nddeapi_NDdeSetTrustedShareW_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x20, 0x32, 0x5f, 0x2f, 0x26, 0xc1, 0x76, 0x10, 0xb5, 0x49, 0x07, 0x4d, 0x07, 0x86, 0x19, 0xda};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 2);
        const UINT16_T OPNUM = 0x0c;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Nddeapi_NDdeSetTrustedShareW exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Lsarpc_DsRoleUpgradeDownlevelServer_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1, 0xd0, 0x11, 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5};
        const UINT32_T VERSION = MAKE_RPC_VERSION(0, 0);
        const UINT16_T OPNUM = 0x09;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Lsarpc_DsRoleUpgradeDownlevelServer exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Msgsvcsend_NetrSendMessage_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xf8, 0x91, 0x7b, 0x5a, 0x00, 0xff, 0xd0, 0x11, 0xa9, 0xb2, 0x00, 0xc0, 0x4f, 0xb6, 0xe6, 0xfc};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        UINT8_T * p = data;
            
        p += parseCvstring(p, dataLength - (p - data));
        p += parseCvstring(p, dataLength - (p - data));
        
        p += 4; // max_count: UINT32_T;
        p += 4; // offset: UINT32_T;
        UINT32_T actual_count; // actual_count: UINT32_T;
        actual_count = *((UINT32_T*)p);
        p += 4;
        
        if(actual_count > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Msgsvcsend_NetrSendMessage exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_ISystemActivator_RemoteCreateInstance_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
        const UINT32_T VERSION = MAKE_RPC_VERSION(0, 0);
        const UINT16_T OPNUM_8205 = 0x04;
        const UINT16_T OPNUM_8234 = 0x03;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_8205)
        {
            UINT8_T * p = data;
        
            p += parseOrpcthis(p, dataLength);
        
            if(dataLength - (p - data) > 512)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "ISystemActivator_RemoteCreateInstance exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_8234)
        {
            for(UINT32_T i = 8; i < 40; i++)
            {
                if(i > dataLength || data[i] != 0x31)
                {
                    return FALSE;
                }
            }
            
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "ISystemActivator_RemoteGetClassObject exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_IRemoteActivation_RemoteActivation_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11, 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57};
        const UINT32_T VERSION = MAKE_RPC_VERSION(0, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        UINT8_T * p = data;
        
        p += parseOrpcthis(p, dataLength - (p - data));
        p += 16;
        p += 4;
        
        p += 4; // max_count: UINT32_T;
        p += 4; // offset: UINT32_T;
        UINT32_T actual_count; // actual_count: UINT32_T;
        actual_count = *((UINT32_T*)p);
        p += 4;
        
        if(actual_count > 0x20)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "IRemoteActivation_RemoteActivation exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_NsiC_nsi_binding_lookup_begin_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x14, 0xb5, 0xfb, 0xd3, 0x3b, 0x0e, 0xcb, 0x11, 0x8f, 0xad, 0x08, 0x00, 0x2b, 0x1d, 0x29, 0xc3};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x00;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "NsiC_nsi_binding_lookup_begin exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_Irot_IrotIsRunning_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x60, 0x9e, 0xe7, 0xb9, 0x52, 0x3d, 0xce, 0x11, 0xaa, 0xa1, 0x00, 0x00, 0x69, 0x01, 0x29, 0x3f};
        const UINT32_T VERSION = MAKE_RPC_VERSION(2, 2);
        const UINT16_T OPNUM = 0x02;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Irot_IrotIsRunning exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }
    
    BOOL_T Is_Veritas_14020_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xd0, 0x1f, 0x84, 0x93, 0xce, 0x16, 0xce, 0x11, 0x85, 0x0d, 0x02, 0x60, 0x8c, 0x44, 0x96, 0x7b};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x07;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "Veritas_14020 exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_CA_21221_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xf0, 0x6b, 0x24, 0xdc, 0x7a, 0x7a, 0xce, 0x11, 0x9f, 0x88, 0x00, 0x80, 0x5f, 0xe4, 0x38, 0x38};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_21221 = 0x2d;
        const UINT16_T OPNUM_22005 = 0x2b;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_21221)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "CA_21221 exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_22005)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "CA_22005 exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }

    BOOL_T Is_CA_22006_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xf0, 0x3d, 0xb9, 0x62, 0x02, 0x8b, 0xce, 0x11, 0x87, 0x6c, 0x00, 0x80, 0x5f, 0x84, 0x28, 0x37};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM_22006 = 0x25;
        const UINT16_T OPNUM_22010 = 0xbf;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 2;
        
        if(opnum == OPNUM_22006)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "CA_22006 exploit.\n"););
                return TRUE;
            }
        }
        else if(opnum == OPNUM_22010)
        {
            if(dataLength > 256)
            {
                matchedNum += 1;
                OUTPUT_WRAP(fprintf(stdout, "CA_22010 exploit.\n"););
                return TRUE;
            }
        }
        
        return FALSE;
    }

    BOOL_T Is_CA_24947_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0x90, 0x28, 0x74, 0x3d, 0x7c, 0x39, 0xcf, 0x11, 0x9b, 0xf1, 0x00, 0x80, 0x5f, 0x88, 0xcb, 0x72};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0xff;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "CA_24947 exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }

    BOOL_T Is_CA_20365_Exploit(UINT8_T uuid[], UINT32_T version, UINT16_T opnum, UINT8_T * data, UINT32_T dataLength)
    {
        const UINT8_T UUID[] = {0xe0, 0x5e, 0x43, 0x88, 0x1a, 0x86, 0xce, 0x11, 0xb8, 0x6b, 0x00, 0x00, 0x1b, 0x27, 0xf6, 0x56};
        const UINT32_T VERSION = MAKE_RPC_VERSION(1, 0);
        const UINT16_T OPNUM = 0x01;
    
        for(int i = 0; i < 16; i++)
        {
            if(uuid[i] != UUID[i])
            {
                return FALSE;
            }
        }
        
        if(version != VERSION)
        {
            return FALSE;
        }
        
        siSize += 1;
        
        if(opnum != OPNUM)
        {
            return FALSE;
        }
        
        if(dataLength > 256)
        {
            matchedNum += 1;
            OUTPUT_WRAP(fprintf(stdout, "CA_20365 exploit.\n"););
            return TRUE;
        }
        
        return FALSE;
    }
    
    inline void parseDceRpcBind(Buffer * buffer, UINT32_T length)
    {
        UINT16_T maxXmitFrag;
        buffer->readUInt16(&maxXmitFrag);
        
        UINT16_T maxRecvFrag;
        buffer->readUInt16(&maxRecvFrag);
        
        UINT32_T assocGroupID;
        buffer->readUInt32(&assocGroupID);
        
        UINT8_T nContextElem = buffer->readUInt8();
        
        buffer->skip(3);
        
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
    
    inline void parseDceRpcBindAck(Buffer * buffer, UINT32_T length)
    {
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
    
    inline void parseDceRpcRequest(Buffer * buffer, UINT32_T length)
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
            
			if(seqMatch->count > 0)
            {
                Is_Trend_Micro_25395_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Samba_24198_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Samba_23973_or_24197_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_MS_Svcctl_ChangeServiceConfig2A_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Wkssvc_NetWkstaEnumUsers_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Srvsvc_NetPathCanonicalize_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Dnsserver_DnssrvQuery_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Rras_RasRpcSetUserPreferences_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Davclntrpc_DavrCreateConnection_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_IXnRemote_BuildContextW_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Spoolss_AddPrinterEx_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Tapsrv_ClientAttach_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Ntsvcs_PNP_QueryResConfList_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Qmcomm_QMDeleteObject_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Llslicense_LlsrLicenseRequestW_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Nddeapi_NDdeSetTrustedShareW_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Lsarpc_DsRoleUpgradeDownlevelServer_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Msgsvcsend_NetrSendMessage_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_ISystemActivator_RemoteCreateInstance_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_IRemoteActivation_RemoteActivation_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_NsiC_nsi_binding_lookup_begin_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Irot_IrotIsRunning_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_Veritas_14020_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_CA_21221_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_CA_22006_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_CA_24947_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                Is_CA_20365_Exploit(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
            }
            else
            {
                Matching_Func_Type matching_func = NULL;
    
                Item * p_item = &(array[0][syntaxID.uuid[0]]);
                
                if(p_item->state == ITEM_FUNC)
                {
                    matching_func = p_item->func;
                }
                else if(p_item->state == ITEM_NEXT)
                {
                    unsigned int array_index = p_item->next;
                    Item * p_item2 = &(array[array_index][syntaxID.uuid[1]]);
                    

                    if(p_item2->state == ITEM_FUNC)
                    {
                        matching_func = p_item2->func;
                    }
                }
                
                if(matching_func != NULL)
                {
                    (this->*matching_func)(syntaxID.uuid, syntaxID.version, opnum, stub, stubLength);
                }
            }
            
            if(printcs->count > 0)
            {
                Connection * conn = flow->getConnection();
                if(reassembled->count == 1)
                {
                    fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                }
                else
                {
                    fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                }
                
                fprintf(stdout, "Si %u Ai %u Bi 0\n", siSize, siSize);
                
                if(siSize > 0)
                {
                    aiSize = count(opnumVector.begin(), opnumVector.end(), opnum);
                    
                    if(reassembled->count == 1)
                    {
                        fprintf(stdout, "Connection %u: ", conn->tuple5.origIP);
                    }
                    else
                    {
                        fprintf(stdout, "Connection %s: ", conn->tuple5.toString().c_str());
                    }
                    fprintf(stdout, "Si %u Ai %u Bi 0\n", matchedNum, aiSize);
                }
                
                if(siSize > maxSiSize)
                {
                    maxSiSize = siSize;
                }
                
                if(siSize > maxAiSize)
                {
                    maxAiSize = siSize;
                }
                
                if(aiSize > maxAiSize)
                {
                    maxAiSize = aiSize;
                }
            }
        }
        
        buffer->skip(length - 8);
    }
    
    inline void parseDceRpcResponse(Buffer * buffer, UINT32_T length)
    {
        UINT32_T allocHint;
        buffer->readUInt32(&allocHint);
        
        UINT16_T ctxID;
        buffer->readUInt16(&ctxID);
        
        UINT8_T cancelCount = buffer->readUInt8();
        
        buffer->readUInt8();
        
        buffer->skip(length - 8); // stub
    }
    
    inline void parseDceRpcFault(Buffer * buffer, UINT32_T length)
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
        
        if(rpcVer != 5)
        {
            ReportError(flow->getConnection(), "RPC version is not 5!\n");
        }
        
        UINT8_T rpcVerMinor = buffer->readUInt8();
        
        UINT8_T ptype = buffer->readUInt8();
        
        UINT8_T pfcFlags = buffer->readUInt8();
        BOOL_T firstFrag = ((pfcFlags & 0x01) != 0);
        BOOL_T lastFrag = ((pfcFlags & 0x02) != 0);
        
        UINT8_T packedDrepIntChar = buffer->readUInt8();
        Endian byteOrder = (packedDrepIntChar >> 4) ? DCE_RPC_LITTLE_ENDIAN : DCE_RPC_BIG_ENDIAN;
        
        UINT8_T floatSpec = buffer->readUInt8();
        buffer->skip(2);
        
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
                parseDceRpcBind(buffer, bodyLength);
                break;
            case DCE_RPC_BIND_ACK:
                parseDceRpcBindAck(buffer, bodyLength);
                break;
            case DCE_RPC_REQUEST:
                parseDceRpcRequest(buffer, bodyLength);
                break;
            case DCE_RPC_RESPONSE:
                parseDceRpcResponse(buffer, bodyLength);
                break;
            case DCE_RPC_FAULT:
                parseDceRpcFault(buffer, bodyLength);
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
                parseDceRpcBind(&dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_BIND_ACK:
                parseDceRpcBindAck(&dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_REQUEST:
                parseDceRpcRequest(&dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_RESPONSE:
                parseDceRpcResponse(&dceRpcReassemblyBuffer, dataLength);
                break;
            case DCE_RPC_FAULT:
                parseDceRpcFault(&dceRpcReassemblyBuffer, dataLength);
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
};

#endif
