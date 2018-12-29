#include "NetShield.h"
#include "Global.h"
#include "Param.h"
#include "Scheduler.h"
#include "Util.h"
#include "Thread.h"
#include "Libnids.h"
#include "ReassembledFile.h"
#include "HTTPAnalyzer.h"
#include "DCERPCAnalyzer.h"
#include "TCPReassembler.h"
#include "UDPReassembler.h"
#include "DFAStruct.h"
#include "DFAMatcher.h"
#include "IntRangeStruct.h"
#include "TrieStruct.h"
#include "TrieMatcher.h"
#ifndef WIN64
#include "Libnids.h"
#include "PcapFilter.h"
#endif

#include "tinyxml/tinyxml.h"

#include <iostream>
#include <sstream>
#include <string>

using namespace std;

#ifdef __cplusplus

extern "C" {
    
#endif
    
#ifdef WIN32
#include <crtdbg.h>
#include "win32/pcap.h"
#include "win32/nids.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libpcap.lib")
#pragma comment(lib, "libnids.lib")
FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]};
#else
#include <pcap.h>
#endif
    
#ifdef __cplusplus
    
}

#endif

Scheduler * scheduler = NULL;

struct timeval startTime;
struct timeval endTime;
struct timeval diffTime;

VOID_T displayStat()
{
    printf("\nNetShield finished\n");
    printf("Time: %lu.%lu s\n", (unsigned long)diffTime.tv_sec, (unsigned long)diffTime.tv_usec);

#ifndef WIN64
    struct pcap_stat stat;
    if(intf->count > 1 && nids_stat(&stat) == 0)
    {    
        printf("%u packets captured\n%u packets received by filter\n%u packets dropped by kernel\n", 
            stat.ps_recv + stat.ps_drop, stat.ps_recv, stat.ps_drop);
    }
#endif

	if(reassembled->count > 0 && protocol.tlp != TLP_UDP)
    {
        printf("Accumulated flow number: %u\n", scheduler->accConnectionNum);
    }
    else if(trace->count > 0 && protocol.tlp == TLP_TCP)
    {
        printf("Max live connection number: %u\n", maxLiveConnectionNum);
        printf("Max live flow number: %u\n", maxLiveConnectionNum * 2);
        printf("Accumulated connection number: %u\n", scheduler->accConnectionNum);
        printf("Accumulated flow number: %u\n", scheduler->accConnectionNum * 2);
    }
    
    if((protocol == PROTOCOL_HTTP && seqMatch->count == 0) || protocol == PROTOCOL_DCE_RPC)
    {
        printf("Accumulated matched flow number: %u\n", accMatchedFlowNum);
        
        // if(silent->count == 0)
        {
            map<UINT16_T, UINT32_T>::iterator it = ruleMap.begin();
            while(it != ruleMap.end())
            {
                printf("Rule %u matched %u time(s)\n", (*it).first, (*it).second);
                it++;
            }
        }
    }
    
    if(tcpReassembly->count > 0)
    {
        printf("TCP reassembly flow number: %u\n", TCPReassembler::flowNum);
        printf("TCP reassembly app bytes: %u\n", TCPReassembler::appBytes);
        
        char * logFilePath = new char[strlen(writeFile->filename[0]) + 32];
        sprintf(logFilePath, "%s.tcp.log", writeFile->filename[0]);
        FILE * logFile = fopen(logFilePath, "w");
        fprintf(logFile, "Accumulated connection number: %u\n", scheduler->accConnectionNum);
        fprintf(logFile, "TCP reassembly flow number: %u\n", TCPReassembler::flowNum);
        fprintf(logFile, "TCP reassembly app bytes: %u\n", TCPReassembler::appBytes);
        fclose(logFile);
    }
    
    if(udpReassembly->count > 0)
    {
        printf("UDP reassembly packet number: %u\n", UDPReassembler::packetNum);
        printf("UDP reassembly app bytes: %u\n", UDPReassembler::appBytes);
        
        char * logFilePath = new char[strlen(writeFile->filename[0]) + 32];
        sprintf(logFilePath, "%s.udp.log", writeFile->filename[0]);
        FILE * logFile = fopen(logFilePath, "w");
        fprintf(logFile, "UDP reassembly packet number: %u\n", UDPReassembler::packetNum);
        fprintf(logFile, "UDP reassembly app bytes: %u\n", UDPReassembler::appBytes);
        fclose(logFile);
    }
    
    if(protocol == PROTOCOL_HTTP)
    {
        printf("Length struct max total size = %u bytes\n", maxIntRangeStructKeyTotalSize + maxIntRangeStructDataTotalSize);        
        printf("Length state max total size = %u bytes\n", maxIntRangeMatcherTotalSize);
        
        printf("DFA struct max total size = %u bytes\n", maxDFAStructTotalSize);
        printf("DFA state max total size = %u bytes\n", maxDFAMatcherTotalSize);
        
        printf("Trie struct max total size = %u bytes\n", maxTrieStructTotalSize);
        printf("Trie state max total size = %u bytes\n", maxTrieMatcherTotalSize);
    }
    
    if (printcs->count > 0)
    {
        printf("maxSiSize = %u\n", maxSiSize);
        printf("maxAiSize = %u\n", maxAiSize);
        printf("maxBiSize = %u\n", maxBiSize);
    }
}

BOOL ctrlHandler(DWORD fdwCtrlType) 
{ 
    switch(fdwCtrlType) 
    { 
        // Handle the CTRL-C signal. 
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
#if defined(WIN32) || defined(WIN64)
            ns_gettimeofday(&endTime, NULL);
#else
            bzero((char *)&tz, sizeof(tz));
            gettimeofday(&endTime, &tz);
#endif

            TIMERSUB(&endTime, &startTime, &diffTime);
            displayStat();
            exit(0);
            return FALSE;
        default:
            return FALSE;
    }
}

int main(int argc, char ** argv)
{
    /*
    DFAStruct<INT32_T> * dfa = new DFAStruct<INT32_T>;
    dfa->compile("/0/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/1/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/2/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/3/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/4/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/5/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/6/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/7/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/8/");
    dfa = new DFAStruct<INT32_T>;
    dfa->compile("/9/");
    */
    
    // DFAStruct<Rule> dfa, dfa1, dfa2;
    // dfa.compile("/aa/|/a*/");
    // dfa1.compile("/aa/");
    // dfa2.compile("/a*/");
    // dfa1.annotate(Rule(0, 1));
    // dfa1.annotate(Rule(1, 1));
    // dfa2.annotate(Rule(0, 2));
    // dfa.annotate(dfa1);
    // dfa.annotate(dfa2);
    // cout << dfa;
    // cout << dfa1;
    // cout << dfa2;
    
    // string regex1 = "/aa/";
    // string regex2 = "/aaa$/";
    // string regex = regex1 + "|" + regex2;
    // DFAStruct<Rule> dfa, dfa1, dfa2;
    // dfa.compile(regex);
    // dfa1.compile(regex1);
    // dfa2.compile(regex2);
    // dfa1.annotate(Rule(0, 1), hasDollar(regex1));
    // dfa1.annotate(Rule(1, 1), hasDollar(regex1));
    // dfa2.annotate(Rule(0, 2), hasDollar(regex2));
    // dfa.annotate(dfa1);
    // dfa.annotate(dfa2);
    // DFAMatcher<Rule> dfaMatcher(&dfa);
    // const char * str = "aaa$";
    // dfaMatcher.matchFromScratch((UINT8_T *)str, (UINT8_T *)str + strlen(str));
    // DFAState<Rule> dfaState;
    // dfaState = dfaMatcher.getCurrentState();
    // dfaState = dfaMatcher.getCurrentState();
    // dfaState = dfaMatcher.getCurrentState();
    //     
    // vector<Rule>::const_iterator it = dfaState.dataVector->begin();
    // while(it != dfaState.dataVector->end())
    // {
    //     cout << "\n" << *it;
    //     
    //     it++;
    // }
    // cout << "\n\n";
    
    // IntRangeStruct<Rule> intRangeStruct;
    // intRangeStruct.add(1, Rule(0, 1));
    // intRangeStruct.add(0, Rule(0, 0));
    
    // vector<IntRangeStruct<Rule>::Pair>::const_iterator first, second;
    // intRangeStruct.matchGt(1, &first, &second);
    
    /*
    TrieStruct<Rule> trieStruct;
    trieStruct.add("123456", Rule(0, 1));
    trieStruct.add("123456", Rule(0, 2));
    trieStruct.add("111111", Rule(1, 1));
    trieStruct.add("111111", Rule(1, 2));
    trieStruct.add("111111", Rule(1, 3));
    trieStruct.add("222222", Rule(2, 1));
    trieStruct.add("222222", Rule(2, 2));
    trieStruct.add("", Rule(3, 0));
    trieStruct.add("", Rule(3, 1));
    
    TrieMatcher<Rule> trieMatcher(&trieStruct);
    const char * str = "111111";
    trieMatcher.match((UINT8_T *)str, (UINT8_T *)str + strlen(str));
    TRIEState<Rule> state = trieMatcher.getCurrentState();

	str = "123";
    trieMatcher.match((UINT8_T *)str, (UINT8_T *)str + strlen(str));
	str = "456";
    trieMatcher.match((UINT8_T *)str, (UINT8_T *)str + strlen(str));
    state = trieMatcher.getCurrentState();
    
    str = "";
    trieMatcher.match((UINT8_T *)str, (UINT8_T *)str + strlen(str));
    state = trieMatcher.getCurrentState();

	str = "222222";
    trieMatcher.match((UINT8_T *)str, (UINT8_T *)str + strlen(str));
    state = trieMatcher.getCurrentState();
    
    printf("sizeof(char) = %d\n", sizeof(char));
    printf("sizeof(short) = %d\n", sizeof(short));
    printf("sizeof(int) = %d\n", sizeof(int));
    printf("sizeof(__int64) = %d\n", sizeof(__int64));
    printf("sizeof(long) = %d\n", sizeof(long));
    
    return 0;
    
    */
    
    SYSTEM_INFO siSysInfo;
 
    // Copy the hardware information to the SYSTEM_INFO structure. 
    
    GetSystemInfo(&siSysInfo); 
    
    // Display the contents of the SYSTEM_INFO structure. 
    
    printf("Hardware information: \n");  
    printf("  OEM ID: %u\n", siSysInfo.dwOemId);
    printf("  Page size: %u\n", siSysInfo.dwPageSize); 
    printf("  Minimum application address: %lx\n", 
        siSysInfo.lpMinimumApplicationAddress); 
    printf("  Maximum application address: %lx\n", 
        siSysInfo.lpMaximumApplicationAddress); 
    printf("  Active processor mask: %u\n", 
        siSysInfo.dwActiveProcessorMask);     
    printf("  Number of processors: %u\n", 
        siSysInfo.dwNumberOfProcessors); 
    printf("  Processor Type: %u\n", 
        siSysInfo.dwProcessorType); 
    printf("  Allocation Granularity: %u\n", 
        siSysInfo.dwAllocationGranularity);     
    
    printf("\n");

    const INT8_T * progName = argv[0];
    
    configFile    = arg_file0("c", NULL, "<config file>", "config file.");
    intf          = arg_int0("i", NULL, "<if number>", "listen on the interface specified.");
    filter        = arg_str0("f", NULL, "<pcap filter expression>", "apply pcap filter.");
    /* Parsers of protocol WINRPC and DNS is under development and may not run properly. */
    proto         = arg_str0("p", NULL, "<protocol>", "<HTTP, WINRPC, DNS>, default HTTP.");
    reassembled   = arg_file0("r", NULL, "<reassembled file>", "reassembled file.");
    trace         = arg_file0("t", NULL, "<trace file>", "tcpdump format trace file.");
    writeFile     = arg_file0("w", NULL, "<output file>", "output file.");
    listIF        = arg_lit0("D", NULL, "display the list of the network interfaces.");
    printcs       = arg_lit0(NULL, "cs", "print each step of cs algorithm.");
    initConn      = arg_int0(NULL, "init-conn", "<number>", "initial connection pool size.");
    parseOnly     = arg_lit0(NULL, "parse-only", "parse only.");
    usePac        = arg_lit0(NULL, "use-pac", "use parser generated by Ultrapac.");
    writeLog      = arg_lit0(NULL, "log", "write log.");
    filterError   = arg_lit0(NULL, "filter-error", "filter parsing error, valid only with '--parse-only' and '-w' option.");
    repeat        = arg_int0(NULL, "repeat", "<number>", "repeat running several times, valid only with '-r' option.");
    silent        = arg_lit0(NULL, "silent", "do not display matched rules.");
    tcpReassembly = arg_lit0(NULL, "tcp-reassembly", "tcp reassembly, input and output file specified by '-t' and '-w' option, respectively.");
    udpReassembly = arg_lit0(NULL, "udp-reassembly", "udp reassembly, input and output file specified by '-t' and '-w' option, respectively.");
    seqMatch      = arg_lit0(NULL, "seq-match", "sequantial matching, valid only with '-r' option.");
    help          = arg_lit0(NULL, "help", "print this help and exit.");
    end           = arg_end(20);
    VOID_T * argtable[] = {configFile, intf, filter, proto, reassembled, trace, writeFile, listIF, printcs, initConn, parseOnly, 
                           usePac, writeLog, filterError, repeat, silent, tcpReassembly, udpReassembly, seqMatch, help, end};
    INT32_T err;
    INT32_T exitCode = 0;

    /* verify the argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable) != 0)
    {
        /* NULL entries were detected, some allocations must have failed */
        printf("%s: insufficient memory\n", progName);
        exitCode = 1;
        goto exit;
    }

    /* Parse the command line as defined by argtable[] */
    err = arg_parse(argc, argv, argtable);

    /* If the parser returned any errors then display them and exit */
    if (err > 0)
    {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, end, progName);
        exitCode = 1;
        goto exit;
    }
    
    if(proto->count > 1)
    {
        exitCode = 1;
        goto exit;
    }
    else if(proto->count == 1)
    {
        if(stricmp(proto->sval[0], "HTTP") == 0)
        {
            protocol = PROTOCOL_HTTP;
        }
        else if(stricmp(proto->sval[0], "WINRPC") == 0)
        {
            protocol = PROTOCOL_DCE_RPC;
        }
        else if(stricmp(proto->sval[0], "DNS") == 0)
        {
            protocol = PROTOCOL_DNS;
        }
        else
        {
            fprintf(stderr, "Unknown protocol: %s\n", proto->sval[0]);
            exitCode = 1;
            goto exit;
        }
    }
    else
    {
        protocol = PROTOCOL_HTTP;
    }
    
    if(configFile->count > 1)
    {
        fprintf(stderr, "please use '-c' option once.\n");
        exitCode = 1;
        goto exit;
    }
    else if(configFile->count == 1)
    {
        if(parseOnly->count + tcpReassembly->count + udpReassembly->count > 0)
        {
            fprintf(stderr, "option '-c' is in conflict with '--parse-only', '--tcp-reassembly' or '--udp-reassembly'!\n");
            exitCode = 1;
            goto exit;
        }
        else
        {
            if(config.LoadFile(configFile->filename[0]) == false)
            {
                fprintf(stderr, "Could not load file '%s'. Error='%s'.\n", configFile->filename[0], config.ErrorDesc());
                exit(0);
            }
        }
    }
    else
    {
		if((protocol == PROTOCOL_HTTP || protocol == PROTOCOL_DCE_RPC)&& parseOnly->count + tcpReassembly->count + udpReassembly->count + seqMatch->count + help->count == 0)
        {
            fprintf(stderr, "No config file!\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(seqMatch->count > 0)
    {
        if(reassembled->count == 0 && protocol == PROTOCOL_HTTP)
        {
            fprintf(stderr, "option '--seq-match' is valid only with '-r' option!\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(intf->count + trace->count + reassembled->count > 1 || 
       filter->count > 1)
    {
        exitCode = 1;
        goto exit;
    }
    
    if(listIF->count > 0)
    {
#ifndef WIN64
        pcap_if_t * devpointer = NULL;
        char ebuf[PCAP_ERRBUF_SIZE];
        
        if (pcap_findalldevs(&devpointer, ebuf) < 0)
        {
            fprintf(stderr, "%s", ebuf);
        }
        else
        {
            for(UINT32_T i = 0; devpointer != NULL; i++)
            {
                printf("%d.%s", i + 1, devpointer->name);
                if (devpointer->description != NULL)
                {
                    printf(" (%s)", devpointer->description);
                }
                printf("\n");
                devpointer = devpointer->next;
            }
        }
#endif
        return 0;
    }
    
    if(filterError->count > 1)
    {
        fprintf(stderr, "please use '--filter-error' option once.\n");
        exitCode = 1;
        goto exit;
    }
    else if(filterError->count == 1)
    {
        if(parseOnly->count == 0 || writeFile->count == 0)
        {
            fprintf(stderr, "--filter-error should be use with '--parse-only' and '-w' option.\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(repeat->count > 1)
    {
        fprintf(stderr, "please use '--repeat' option once.\n");
        exitCode = 1;
        goto exit;
    }
    else if(repeat->count == 1)
    {
        if(reassembled->count == 0)
        {
            fprintf(stderr, "please use '--repeat' option with '-r' option.\n");
            exitCode = 1;
            goto exit;
        }
        
        if(repeat->ival[0] <= 0)
        {
            fprintf(stderr, "please specify positive '--repeat' option value.\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(tcpReassembly->count > 1)
    {
        fprintf(stderr, "please use '--tcp-reassembly' option once.\n");
        exitCode = 1;
        goto exit;
    }
    else if(tcpReassembly->count == 1)
    {
        if(trace->count == 0 || writeFile->count == 0)
        {
            fprintf(stderr, "--tcp-reassembly should be use with '-t' and '-w' option.\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(udpReassembly->count > 1)
    {
        fprintf(stderr, "please use '--udp-reassembly' option once.\n");
        exitCode = 1;
        goto exit;
    }
    else if(udpReassembly->count == 1)
    {
        if(trace->count == 0 || writeFile->count == 0)
        {
            fprintf(stderr, "--udp-reassembly should be use with '-t' and '-w' option.\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(filterError->count + tcpReassembly->count + udpReassembly->count > 1)
    {
        fprintf(stderr, "option '--filter-error', '--tcp-reassembly' and '--udp-reassembly' are in conflict.\n");
        exitCode = 1;
        goto exit;
    }
    
    if(proto->count + tcpReassembly->count + udpReassembly->count > 1)
    {
        fprintf(stderr, "option '-p', '--tcp-reassembly' and '--udp-reassembly' are in conflict.\n");
        exitCode = 1;
        goto exit;
    }
    
    if(writeFile->count > 1)
    {
        fprintf(stderr, "'-w' option should be used once only.\n");
        exitCode = 1;
        goto exit;
    }
    else if(writeFile->count == 1)
    {
        if(filterError->count + tcpReassembly->count + udpReassembly->count == 0)
        {
            fprintf(stderr, "'-w' option should be used with options that will generate output data, like '--filter-error'.\n");
            exitCode = 1;
            goto exit;
        }
    }
    
    if(initConn->count > 1)
    {
        fprintf(stderr, "please use '--init-conn' option once.\n");
        exitCode = 1;
        goto exit;
    }
    else if(initConn->count == 1)
    {
        if(initConn->ival[0] <= 0)
        {
            fprintf(stderr, "please specify positive '--init-conn' option value.\n");
            exitCode = 1;
            goto exit;
        }
        else
        {
            initConnNum = initConn->ival[0];
        }
    }
    else
    {
        initConnNum = CONNECTION_POOL_INIT_SIZE;
    }

exit:
    
    /* special case: '--help' takes precedence over error reporting */
    if (help->count > 0 || exitCode != 0)
    {
        printf("Usage: \n%s", progName);
        arg_print_syntax(stdout, argtable, "\n");
        arg_print_glossary(stdout, argtable, "  %-25s %s\n");
        
        /* deallocate each non-null entry in argtable[] */
        // arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));
        exit(exitCode);
    }
    
    if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ctrlHandler, TRUE))
    {
        fprintf(stderr, "Error: Could not set control handler\n");
    }
    
    if(udpReassembly->count == 1)
    {
        protocol = PROTOCOL_DNS;
    }
    
    if(seqMatch->count > 0)
	{
		if(protocol == PROTOCOL_HTTP)
		{
			HTTPAnalyzerSeqInit();
		}
		else if(protocol == PROTOCOL_DCE_RPC)
		{
			DCERPCAnalyzerSeqInit();
		}
	}
    
    scheduler = new Scheduler(Thread::getMainThread());
    verify(scheduler);

#ifndef WIN64
    Libnids * libnids = NULL;
#endif

    ReassembledFile * reassembledFile = NULL;

#ifndef WIN64
    if(intf->count == 1)
    {
        libnids = new Libnids(protocol.tlp);
        verify(libnids != NULL);
        libnids->setInterface(intf->ival[0]);
    }
    else if(trace->count == 1)
    {
        libnids = new Libnids(protocol.tlp);
        verify(libnids != NULL);
        libnids->setFileToRead(trace->filename[0]);
    }
    else
#endif 
    if(reassembled->count == 1)
    {
        reassembledFile = new ReassembledFile();
        verify(reassembledFile != NULL);
        if(reassembledFile->open(reassembled->filename[0]) < 0 )
        {
            fprintf(stderr, "Cannot open file: %s!\n", reassembled->filename[0]);
            exit(0);
        }
    }
    
    printf("NetShield start working...\n\n");
    
    if(reassembledFile != NULL)
    {
        if(repeat->count == 0)
        {
            fprintf(stdout, "Repeat 1 time(s).\n");
        }
        else
        {
            fprintf(stdout, "Repeat %d time(s).\n", repeat->ival[0]);
        }
    }

#if defined(WIN32) || defined(WIN64)
    ns_gettimeofday(&startTime, NULL);
#else
    struct timezone tz;
    bzero((char *) &tz, sizeof(tz));
    gettimeofday(&startTime, &tz);
#endif

#ifndef WIN64
    if(libnids != NULL)
    {
        if(filter->count == 1)
        {
            libnids->setFilter(filter->sval[0]);
        }
        
        libnids->init();
        libnids->setScheduler(scheduler);
        libnids->run();
    }
    else
#endif

    if(reassembledFile != NULL)
    {
        reassembledFile->setScheduler(scheduler);
        if(repeat->count == 0)
        {
            reassembledFile->run();
        }
        else
        {
            for(INT32_T i = 0; i < repeat->ival[0]; i++)
            {
                reassembledFile->run();
            }
        }
    }
    
#if defined(WIN32) || defined(WIN64)
    ns_gettimeofday(&endTime, NULL);
#else
    bzero((char *)&tz, sizeof(tz));
    gettimeofday(&endTime, &tz);
#endif

    TIMERSUB(&endTime, &startTime, &diffTime);
    
#ifndef WIN64
    if(filterError->count > 0 && trace->count > 0 && writeFile->count > 0)
    {
        /*
        FILE * fp = fopen("map.log", "w");
        map<Tuple5, bool>::iterator it = filterTuple5Map.begin();
        while(it != filterTuple5Map.end())
        {
            fprintf(fp, (*it).second == true ? "Connection: %s true\n" : "Connection: %s false\n", (*it).first.toString().c_str());
            it++;
        }
        fclose(fp);
        */
        
        PcapFilter pcapFilter(trace->filename[0], writeFile->filename[0], &filterTuple5Map);
        pcapFilter.run();
    }
#endif

#ifndef WIN64
    if(libnids != NULL)
    {
        delete libnids;
        libnids = NULL;
    }
#endif

    // Clean up.
	displayStat();

    if(reassembledFile != NULL)
    {
        reassembledFile->close();
        delete reassembledFile;
        reassembledFile = NULL;
    }
    
    delete scheduler;
    
    /* deallocate each non-null entry in argtable[] */
    arg_freetable(argtable, sizeof(argtable)/sizeof(argtable[0]));
    
    return 0;
}
