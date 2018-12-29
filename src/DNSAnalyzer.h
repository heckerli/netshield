#ifndef _DNS_ANALYZER_H_
#define _DNS_ANALYZER_H_

#include "NetShield.h"
#include "PacketAnalyzer.h"

#define TYPE_A          1
#define TYPE_NS         2
#define TYPE_MD         3
#define TYPE_MF         4
#define TYPE_CNAME	    5
#define TYPE_SOA        6
#define TYPE_MB         7
#define TYPE_MG         8
#define TYPE_MR         9
#define TYPE_NULL       10
#define TYPE_WKS        11
#define TYPE_PTR        12
#define TYPE_HINFO      13
#define TYPE_MINFO      14
#define TYPE_MX         15
#define TYPE_TXT        16
#define TYPE_AAAA       28
#define TYPE_NBS        32
#define TYPE_A6         38
#define TYPE_EDNS       41

class DNSAnalyzer : public PacketAnalyzer
{
public:
    DNSAnalyzer()
    {
        pduNum = 0;
        pduSize = 0;
    }
    
    ~DNSAnalyzer()
    {
        // fprintf(stderr, "DNSAnalyzer %X: %u PDU parsed, %u bytes\n", this, pduNum, pduSize);
    }
    
    virtual INT32_T run()
    {
        // DEBUG_WRAP(DebugMessage("DNSAnalyzer: 0x%.8X, run()\n", this););
    
        while(1)
        {
            // DEBUG_WRAP(DebugMessage("DNSAnalyzer: 0x%.8X, PDU length = %d\n", this, length););
            UINT32_T bufferLength = buffer->getLength();
            INT32_T length = parseDNSMessage(buffer);
            
            pduNum += 1;
            pduSize += length;
            
            validPduNum += 1;
            
			/*
            if(bufferLength != length)
            {
                fprintf(stderr, "DNS PDU %u: length != bufferLength\n", packetNum);
            }
			*/
        }
    
    	return 0;
    }

protected:
    UINT32_T pduNum;
    UINT32_T pduSize;
    
#ifdef DEBUG
    inline void parseDNSName(Buffer * buffer)
    {
        register bool last;
        register UINT8_T length;
        register UINT8_T label_type;

        do
        {
            length = (buffer)->readUInt8();

            label_type = length >> 6;
            last = (length == 0) || (label_type == 3);

            switch(label_type)
            {
            case 0:
                (buffer)->skip(length);
                break;

            case 3:
                (buffer)->readUInt8();
                break;
            default:
                break;
            }
        }while(last == false);
    }
#else
#define parseDNSName(buffer) \
    { \
        register bool last; \
        register UINT8_T length; \
        register UINT8_T label_type; \
                            \
        do \
        { \
            length = (buffer)->readUInt8(); \
                                          \
            label_type = length >> 6; \
            last = (length == 0) || (label_type == 3); \
                                                       \
            switch(label_type) \
            { \
            case 0: \
                (buffer)->skip(length); \
                break; \
                       \
            case 3: \
                (buffer)->readUInt8(); \
                break; \
            default: \
                break; \
            } \
        }while(last == false); \
    }
#endif
    
    inline void parseDNSRdata(Buffer * buffer, UINT16_T rr_type, UINT16_T rr_class, UINT16_T rr_rdlength)
    {        
        switch(rr_type)
        {
        case TYPE_A:
            if(rr_rdlength == 0)
            {
                return;
            }
            buffer->skip(4); // TYPE_A 	   -> type_a: 	  UINT32_T;
            break;
        case TYPE_NS:
            if(rr_rdlength == 0)
            {
                return;
            }
    	    parseDNSName(buffer); // TYPE_NS    -> type_ns:	  DNS_name(msg);
    	    break;
    	case TYPE_CNAME:
    	    if(rr_rdlength == 0)
            {
                return;
            }
    	    parseDNSName(buffer); // TYPE_CNAME -> type_cname: DNS_name(msg);
    	    break;
    	case TYPE_SOA:
    	    if(rr_rdlength == 0)
            {
                return;
            }
    	    // TYPE_SOA   -> type_soa:	  DNS_rdata_SOA(msg);
    	    parseDNSName(buffer);
    	    parseDNSName(buffer);
    	    buffer->skip(4 * 5);
    	    break;
    	case TYPE_PTR:
    	    if(rr_rdlength == 0)
            {
                return;
            }
    	    parseDNSName(buffer); // TYPE_PTR   -> type_ptr:	  DNS_name(msg);
    	    break;
    	case TYPE_MX:
    	    if(rr_rdlength == 0)
            {
                return;
            }
    	    // TYPE_MX    -> type_mx:	  DNS_rdata_MX(msg);
    	    buffer->skip(2);
    	    parseDNSName(buffer);
    	    break;
    	case TYPE_AAAA:
    	case TYPE_A6:
    	    if(rr_rdlength == 0)
            {
                return;
            }
    	    //TYPE_AAAA, TYPE_A6 -> type_aaaa:  UINT32_T[4];
    	    buffer->skip(4 * 4);
    	    break;
    
    	default:
    	    buffer->skipFlow();
    	    break;
        }
    }
    
    inline UINT32_T parseDNSMessage(Buffer * buffer)
    {
        INT32_T byteCountBegin = buffer->getByteCount();
        
        UINT16_T qdcount; // qdcount	: UINT16_T;
    	UINT16_T ancount; // ancount	: UINT16_T;
    	UINT16_T nscount; // nscount	: UINT16_T;
    	UINT16_T arcount; // arcount	: UINT16_T;
    	        
        // id	: UINT16_T;
    	// qrop	: UINT16_T;
    	buffer->skip(4);
    	
    	buffer->readUInt16Ntohs(&qdcount);
    	// printf("qdcount = %d\n", qdcount);
    	
    	buffer->readUInt16Ntohs(&ancount);
    	// printf("ancount = %d\n", ancount);
    	
    	buffer->readUInt16Ntohs(&nscount);
    	// printf("nscount = %d\n", nscount);
    	
    	buffer->readUInt16Ntohs(&arcount);
    	// printf("arcount = %d\n", arcount);
    	
    	// question:	DNS_question(this)[header.qdcount];
    	for(UINT32_T i = 0; i < qdcount; i++)
        {
            parseDNSName(buffer);
            
            // qtype:	UINT16_T;
    	    // qclass:	UINT16_T;
    	    buffer->skip(4);
        }
        
        // answer:		DNS_rr(this, DNS_ANSWER)[header.ancount];
        for(UINT32_T i = 0; i < ancount; i++)
        {
            // rr_name:	DNS_name(msg);
            parseDNSName(buffer);
            
            UINT16_T rr_type; // rr_type:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_type);
    	    
    	    UINT16_T rr_class; // rr_class:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_class);
    	    
    	    buffer->skip(4); // rr_ttl:		UINT32_T;
    	    
    	    UINT16_T rr_rdlength; // rr_rdlength:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_rdlength);
    	    
    	    // rr_rdata:	DNS_rdata(msg, rr_type, rr_class) &length = rr_rdlength;
    	    parseDNSRdata(buffer, rr_type, rr_class, rr_rdlength);
        }
        
        // authority:	DNS_rr(this, DNS_AUTHORITY)[header.nscount];
        for(UINT32_T i = 0; i < nscount; i++)
        {
            // rr_name:	DNS_name(msg);
            parseDNSName(buffer);
            
            UINT16_T rr_type; // rr_type:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_type);
    	    
    	    UINT16_T rr_class; // rr_class:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_class);
    	    
    	    buffer->skip(4); // rr_ttl:		UINT32_T;
    	    
    	    UINT16_T rr_rdlength; // rr_rdlength:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_rdlength);
    	    
    	    // rr_rdata:	DNS_rdata(msg, rr_type, rr_class) &length = rr_rdlength;
    	    parseDNSRdata(buffer, rr_type, rr_class, rr_rdlength);
        }
        
        // additional:	DNS_rr(this, DNS_ADDITIONAL)[header.arcount];
        for(UINT32_T i = 0; i < arcount; i++)
        {
            // rr_name:	DNS_name(msg);
            parseDNSName(buffer);
            
            UINT16_T rr_type; // rr_type:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_type);
    	    
    	    UINT16_T rr_class; // rr_class:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_class);
    	    
    	    buffer->skip(4); // rr_ttl:		UINT32_T;
    	    
    	    UINT16_T rr_rdlength; // rr_rdlength:	UINT16_T;
            buffer->readUInt16Ntohs(&rr_rdlength);
    	    
    	    // rr_rdata:	DNS_rdata(msg, rr_type, rr_class) &length = rr_rdlength;
    	    parseDNSRdata(buffer, rr_type, rr_class, rr_rdlength);
        }
        
        return buffer->getByteCount() - byteCountBegin;
    }

};

#endif
