#include "PcapFilter.h"

PcapFilter::PcapFilter(const char * inputFile, const char * outputFile, map<Tuple5, bool> * tuple5Map)
{
    this->inputFile = inputFile;
    this->outputFile = outputFile;
    this->tuple5Map = tuple5Map;
    
    this->linkOffset = 0;
    this->pcapHandle = NULL;
    this->outputDumper = NULL;
}

PcapFilter::~PcapFilter()
{
}

void PcapFilter::pcapCallback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet)
{
    PcapFilter * pcapFilter = (PcapFilter *)args;
    
    const u_char * ip_offset = (const u_char *)(packet + pcapFilter->linkOffset);
    if(*(ip_offset + 9) != 6) // TCP
    {
        return;
    }
    
    const u_int sip = (*((u_int *)(ip_offset + 4 * 3)));
    const u_int dip = (*((u_int *)(ip_offset + 4 * 4)));
    
    const u_char * tcp_offset = ip_offset + ((*ip_offset) & 0x0f) * 4;
    const u_short sport = ntohs(*((unsigned short *)(tcp_offset + 0)));
    const u_short dport = ntohs(*((unsigned short *)(tcp_offset + 2)));
    const u_int seq_num = ntohl(*((u_int *)(tcp_offset + 4 * 1)));
    const u_int ack_num = ntohl(*((u_int *)(tcp_offset + 4 * 2)));
    const bool syn = ((*(tcp_offset + 13)) & 0x02) != 0;
    const bool fin = ((*(tcp_offset + 13)) & 0x01) != 0;
    const bool rst = ((*(tcp_offset + 13)) & 0x04) != 0;
    const bool ack = ((*(tcp_offset + 13)) & 0x10) != 0;
    
    Tuple5 tuple5;
    tuple5.origIP = sip;
    tuple5.origPort = sport;
    tuple5.respIP = dip;
    tuple5.respPort = dport;
    tuple5.protocol = 6; // TCP
    
    Tuple5::sort(&tuple5);
    
    if(pcapFilter->tuple5Map->find(tuple5) == pcapFilter->tuple5Map->end())
    {
        return;
    }

	if((*(pcapFilter->tuple5Map))[tuple5] == false)
	{
        return;
	}

    if(pcapFilter->outputDumper != NULL)
    {
        pcap_dump((u_char *)(pcapFilter->outputDumper), header, packet);
    }
}

void PcapFilter::run()
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    
    if ((pcapHandle = pcap_open_offline(inputFile, pcap_errbuf)) == NULL)
	{
	    fprintf(stderr, "%s.\n", pcap_errbuf);
	    return;
    }
    
    outputDumper = pcap_dump_open(pcapHandle, outputFile);
	if(outputDumper == NULL)
	{
	    fprintf(stderr, "%s.\n", pcap_geterr(pcapHandle));
	}
	    
    int linktype = pcap_datalink(pcapHandle);
    switch(linktype)
    {
#ifdef DLT_NULL
    case DLT_NULL:
        linkOffset = 4;
        break;
#endif        
    case DLT_EN10MB:
        linkOffset = 14;
        break;
    case DLT_PPP:
        linkOffset = 4;
        break;
    /* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
    case DLT_IEEE802:
        linkOffset = 22;
        break;
    
    case DLT_RAW:
    case DLT_SLIP:
        linkOffset = 0;
        break;
#define DLT_LINUX_SLL   113
    case DLT_LINUX_SLL:
        linkOffset = 16;
        break;
#ifdef DLT_FDDI
    case DLT_FDDI:
        linkOffset = 21;
        break;
#endif        
#ifdef DLT_PPP_SERIAL 
    case DLT_PPP_SERIAL:
        linkOffset = 4;
        break;
#endif
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
    case DLT_PRISM_HEADER:
#endif
    case DLT_IEEE802_11:
    /* wireless, need to calculate offset per frame */
#endif
    default:
        fprintf(stderr, "link type unknown");
        return;
    }
    
    pcap_loop(pcapHandle, -1, pcapCallback, (u_char *)this);
    
    pcap_close(pcapHandle);
    pcapHandle = NULL;
    
    pcap_dump_close(outputDumper);
    outputDumper = NULL;
}
