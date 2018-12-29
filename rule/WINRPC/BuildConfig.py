from sys import *
from string import *
import os
import re
import sys

XML_HEAD = """<?xml version="1.0" encoding="ASCII" ?>
<NetShield>
	<WINRPC>
		<Signature>
			<Rules>
"""

XML_TAIL = """			</Rules>
		</Signature>
	</WINRPC>
</NetShield>
"""

def reverse_uuid_string(uuid_part):
    out = ""
    i = len(uuid_part) - 2
    while i >= 0:
        out += uuid_part[i:i+2]
        i -= 2
    
    return out

def parse_packed_drep(packed_drep):
    result = re.search(r"\\x([0-9a-zA-Z]{2})\\x([0-9a-zA-Z]{2})\\x([0-9a-zA-Z]{2})\\x([0-9a-zA-Z]{2})", packed_drep)
    if result == None:
        sys.stderr.write("Unrecognized packed_drep: %s!\n" % packed_drep)
        sys.exit(0)

    packed_drep_str = "0x" + result.group(1) + " 0x" + result.group(2) + " 0x" + result.group(3) + " 0x" + result.group(4)
    packed_drep_int = atol(result.group(4) + result.group(3) + result.group(2) + result.group(1), 16)
    packed_drep_hex = result.group(4) + result.group(3) + result.group(2) + result.group(1)
    
    return (packed_drep_str, packed_drep_hex)

def make_version(major, minor):
    ver = (((major & 0xff) << 24) | ((major & 0xff00) << 8) | ((minor & 0xff) << 8) | ((minor & 0xff00) >> 8))
    return ver

def uuidHexToArray(uuid_hex):
    uuidArray = ""
    
    i = 0
    while(i < 32):
        if len(uuidArray) == 0:
            uuidArray += "0x"
        else:
            uuidArray += ", 0x"
        uuidArray += uuid_hex[i:i+2]
        i += 2
    
    return uuidArray

if __name__ == '__main__':
    cfg = open(argv[2], "w")
    seq = open("DCERPCAnalyzerSeq.cpp", "w")
    
    seqHead = """#include \"HTTPAnalyzerSeq.h\"
#include \"DCERPCAnalyzer.h\"

"""

    seqInit = """
void DCERPCAnalyzerSeqInit()
{
"""
    
    seqBody = ""
    
    cfg.write(XML_HEAD)
    
    ruleID = 1
    for line in open(argv[1], "r"):
        cfg.write("			    <Rule>\n")
        
        seqBody += ("""void Rule%d_Match(UINT8_T bindRpcVer, UINT32_T bindPackedDrep, 
                 UINT8_T bindAckRpcVer, UINT32_T bindAckPackedDrep, 
                 UINT8_T requestRpcVer, UINT32_T requestPackedDrep, 
                 UINT8_T uuid[], UINT32_T version, UINT16_T opnum, 
                 UINT8_T * stub, UINT32_T stubLength)
{
""" % ruleID);
        
        # cfg.write(line)
        line.strip('\r')
        line.strip('\n')
        line.strip('\r')
        
        result = re.search(r"Signature:\(BIND.rpc_ver==(?P<bind_rpc_ver_str>[0-9]+)\)&&\(BIND\.packed_drep==\"(?P<bind_packed_drep>[^\"]+)\"\)&&\(BIND\.UUID==\"(?P<uuid_str>[-0-9a-zA-Z]+)\"\)&&\(BIND\.ver==\"(?P<version_str>[\.0-9]+)\"\)->\(BIND_ACK\.rpc_ver==(?P<bind_ack_rpc_ver_str>[0-9]+)\)&&\(BIND_ACK\.packed_drep==\"(?P<bind_ack_packed_drep>[^\"]+)\"\)->\(REQUEST\.rpc_ver==(?P<request_rpc_ver_str>[0-9]+)\)&&\(REQUEST\.packed_drep==\"(?P<request_packed_drep>[^\"]+)\"\)&&\(REQUEST\.opnum==(?P<opnum_str>[Xx0-9a-zA-Z]+)\)&&(?P<stub_sig_str>.+)", line)
        if result != None:
            # print result.group(0)
            # break
            bind_rpc_ver_str = result.group("bind_rpc_ver_str")
            bind_packed_drep = result.group("bind_packed_drep")
            uuid_str = result.group("uuid_str")
            version_str = result.group("version_str")
            bind_ack_rpc_ver_str = result.group("bind_ack_rpc_ver_str")
            bind_ack_packed_drep = result.group("bind_ack_packed_drep")
            request_rpc_ver_str = result.group("request_rpc_ver_str")
            request_packed_drep = result.group("request_packed_drep")
            opnum_str = result.group("opnum_str")
            stub_sig_str = result.group("stub_sig_str")
            
            uuid_result = re.search(r"([0-9a-zA-Z]{8})-([0-9a-zA-Z]{4})-([0-9a-zA-Z]{4})-([0-9a-zA-Z]{4})-([0-9a-zA-Z]{12})", uuid_str)
            if uuid_result == None:
                sys.stderr.write("Unrecognized UUID: %s!\n" % uuid_str)
                sys.exit(0)
            
            uuid_hex  = reverse_uuid_string(uuid_result.group(1))
            uuid_hex += reverse_uuid_string(uuid_result.group(2))
            uuid_hex += reverse_uuid_string(uuid_result.group(3))
            uuid_hex += uuid_result.group(4)
            uuid_hex += uuid_result.group(5)
            
            version_result = re.search(r"([0-9]+)\.([0-9]+)", version_str)
            if version_result == None:
                sys.stderr.write("Unrecognized Version: %s!\n" % version_str)
                sys.exit(0)
            
            version_major = version_result.group(1)
            version_minor = version_result.group(2)
            
            version_hex = make_version(int(version_major), int(version_minor))
            
            cfg.write("                    <Bind_rpc_ver Str=\"" + bind_rpc_ver_str + "\"></Bind_rpc_ver>\n")
            
            seqBody += ("    if (bindRpcVer != %s) { return; }\n\n" % bind_rpc_ver_str)
            
            (packed_drep_str, packed_drep_hex) = parse_packed_drep(bind_packed_drep)
            cfg.write("                    <Bind_packed_drep Str=\"" + packed_drep_str + "\" Hex=\"" + packed_drep_hex + "\"></Bind_packed_drep>\n")
            
            seqBody += ("    if (bindPackedDrep != 0x%s) { return; }\n\n" % packed_drep_hex)
            
            cfg.write("                    <Uuid Str=\"" + uuid_str + "\" Hex=\"" + uuid_hex + "\"></Uuid>\n")
            cfg.write("                    <Version Str=\"" + version_str + "\" Hex=\"")
            cfg.write("%.8x" % version_hex)
            cfg.write("\"></Version>\n")
            
            cfg.write("                    <Bind_ack_rpc_ver Str=\"" + bind_ack_rpc_ver_str + "\"></Bind_ack_rpc_ver>\n")
            
            seqBody += ("    if (bindAckRpcVer != %s) { return; }\n\n" % bind_ack_rpc_ver_str)
            
            (packed_drep_str, packed_drep_hex) = parse_packed_drep(bind_ack_packed_drep)
            cfg.write("                    <Bind_ack_packed_drep Str=\"" + packed_drep_str + "\" Hex=\"" + packed_drep_hex + "\"></Bind_ack_packed_drep>\n")
            
            seqBody += ("    if (bindAckPackedDrep != 0x%s) { return; }\n\n" % packed_drep_hex)
            
            cfg.write("                    <Request_rpc_ver Str=\"" + request_rpc_ver_str + "\"></Request_rpc_ver>\n")
            
            seqBody += ("    if (requestRpcVer != %s) { return; }\n\n" % request_rpc_ver_str)
            
            (packed_drep_str, packed_drep_hex) = parse_packed_drep(bind_ack_packed_drep)
            cfg.write("                    <Request_packed_drep Str=\"" + packed_drep_str + "\" Hex=\"" + packed_drep_hex + "\"></Request_packed_drep>\n")
            
            seqBody += ("    if (requestPackedDrep != 0x%s) { return; }\n\n" % packed_drep_hex)
            
            
            seqBody += ("    const UINT8_T UUID[] = { " + uuidHexToArray(uuid_hex) + " };\n\n")
            seqBody += ("""    for(UINT32_T i = 0; i < 16; i++)
    {
        if(uuid[i] != UUID[i])
        {
            return;
        }
    }
    
""")
            
            cfg.write("                    <Opnum Str=\"" + opnum_str + "\" Hex=\"")
            if(opnum_str[0:2] == "0x" or opnum_str[0:2] == "0X"):
                cfg.write("%.4x" % int(opnum_str[2:], 16))
            else:
                cfg.write("%.4x" % int(opnum_str, 10))
            cfg.write("\"></Opnum>\n")
            
            seqBody += ("    if (version != 0x%.8x) { return; }\n\n" % version_hex)
            seqBody += ("    if (opnum != %s) { return; }\n\n" % opnum_str)
            
            # print stub_sig_str
            
            stub_result = re.search(r"\(([^&]+)\)(&&)?([^&]+)?", stub_sig_str)
            
            if stub_result == None:
                sys.stderr.write("Unrecognized Stub signature: %s!\n" % stub_sig_str)
                sys.exit(0)
            
            # print stub_result.group(0)
            # print stub_result.group(1)
            # print stub_result.group(2)
            # print stub_result.group(3)
            
            field_str = stub_result.group(1)
            # print field_str
            
            if field_str[0:4] == "len(":
                len_result = re.search(r"len\(([._0-9a-zA-Z]+)\)(>[=]?)([Xx0-9a-zA-Z]+)", field_str)
                
                field_str = len_result.group(1)
                oprand_str = len_result.group(2)
                value_str = len_result.group(3)
                
                # print field_str
                # print oprand_str
                # print value_str
                
                field_str += ".Length"
            else:
                field_result = re.search(r"([._0-9a-zA-Z]+)(>[=]?)([Xx0-9a-zA-Z]+)", field_str)
                if field_result == None:
                    sys.stderr.write("Unrecognized field signature: %s!\n" % field_str)
                    sys.exit(0)
                
                field_str = field_result.group(1)
                oprand_str = field_result.group(2)
                value_str = field_result.group(3)
                
            field_str = replace(field_str, ".", "_")
            
            value = 0
            if(value_str[0:2] == "0x" or value_str[0:2] == "0X"):
                value = int(value_str[2:], 16)
            else:
                value = int(value_str, 10)
            
            if oprand_str == ">=":
                value -= 1
            
            cfg.write("                    <Stub Field=\"" + field_str + "\" Value=\"" + str(value) + "\"")
            
            seqBody += ("    if (DCERPCAnalyzer::%s(stub, stubLength) <= %d) { return; }\n\n" % (field_str, value))
        
            regex_str = stub_result.group(3)
            
            if regex_str != None:
                regex_result = re.search(r"match_re\(\"([^\"]+)\",REQUEST\.stub\)", regex_str)
                # print regex_result.group(1)
                
                if regex_result != None:
                    cfg.write(" Regex=\"" + regex_result.group(1) + "\"")
                    
                    seqHead += "RegexMatcher * Rule%d_stub_RegexMatcher = NULL;\n" % (ruleID)
                    seqInit += "    Rule%d_stub_RegexMatcher = new RegexMatcher(\"%s\");\n" % (ruleID, regex_result.group(1))
                    seqBody += "    if (Rule%d_stub_RegexMatcher->match(stub, stubLength) == false) { return; }\n\n" % (ruleID)
                    
            cfg.write("></Stub>\n")
        
        seqBody += """    if(ruleMap.find(%d) == ruleMap.end())
    {
        ruleMap[%d] = 1;
    }
    else
    {
        ruleMap[%d] += 1;
    }
    
    if(silent->count == 0)
    {
        printf(\"Rule %d matched!\\n\");
    }
""" % (ruleID, ruleID, ruleID, ruleID)
    
        cfg.write("			    </Rule>\n")
        seqBody += ("}\n\n")
        ruleID += 1
    
    seqInit += "}\n\n"
    
    seq.write(seqHead)
    seq.write(seqInit)
    seq.write(seqBody)
    
    seq.write("""void DCERPCAnalyzerSeqMatch(UINT8_T bindRpcVer, UINT32_T bindPackedDrep, 
                 UINT8_T bindAckRpcVer, UINT32_T bindAckPackedDrep, 
                 UINT8_T requestRpcVer, UINT32_T requestPackedDrep, 
                 UINT8_T uuid[], UINT32_T version, UINT16_T opnum, 
                 UINT8_T * stub, UINT32_T stubLength)
{
""")

    i = 1
    while i < ruleID:
        seq.write("""    Rule%d_Match(bindRpcVer, bindPackedDrep, bindAckRpcVer, bindAckPackedDrep,
        requestRpcVer, requestPackedDrep, uuid, version, opnum, stub, stubLength);\n\n""" % i)
        i += 1
        
    seq.write("}")
    
    seq.close()
    
    cfg.write(XML_TAIL)
    cfg.close()
    