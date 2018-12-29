#ifndef _PCAP_FILTER_H_
#define _PCAP_FILTER_H_

#include "NetShield.h"

#ifdef WIN32
#include "win32/pcap.h"
#else
#include <pcap.h>
#endif

#include <map>

using namespace std;

class PcapFilter
{
public:
    PcapFilter(const char * inputFile, const char * outputFile, map<Tuple5, bool> * tuple5Map);
    ~PcapFilter();
    
    void run();

protected:
    static void pcapCallback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
    
    const char * inputFile;
    const char * outputFile;
    map<Tuple5, bool> * tuple5Map;
    
    unsigned int linkOffset;
    pcap_t * pcapHandle;
    pcap_dumper_t * outputDumper;
};

#endif
