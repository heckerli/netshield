#include <stdio.h>
#include <sys/timeb.h>
#include <time.h>
#include <string>
#include <vector>
#include <map>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef __cplusplus

extern "C" {
	
#endif

#ifdef WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libpcap.lib")
#pragma comment(lib, "libnids.lib")
FILE _iob[3] = {__iob_func()[0], __iob_func()[1], __iob_func()[2]};
#endif

#include "nids.h"
#include "pcap.h"
	
#ifdef __cplusplus
	
}

#endif

#include "BlockList.h"
#include "MemPool.h"
#include "ObjectPool.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#define TIMERSUB(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

class Connection
{
public:
    BlockList origList;
    BlockList respList;
};

ObjectPool<Connection> connPool(100000);
std::map<Connection *, bool> connMap;
MemPool memPool(400000);
FILE * combined_file = NULL;
unsigned int conn_num = 0;
unsigned int flow_num = 0; // count only if the flow has valid data;
unsigned int app_bytes = 0;

void addToList(char * data, int dataLength, BlockList * l)
{
    while(dataLength > 0)
    {
        Block * block = memPool.get();
        
        if(dataLength > DATA_SEGMENT_SIZE)
        {
            block->dataLength = DATA_SEGMENT_SIZE;
            memcpy(block->data, data, DATA_SEGMENT_SIZE);
        }
        else
        {
            block->dataLength = dataLength;
            memcpy(block->data, data, dataLength);
        }
        
        l->pushBack(block);
        dataLength -= DATA_SEGMENT_SIZE;
        data += DATA_SEGMENT_SIZE;
    }
}

void writeToFile(FILE * fp, char direction, BlockList * l)
{
    Block * block = l->head;
    if(block == NULL)
    {
        return;
    }
    
    l->tail->next = NULL;
    
    unsigned int length = 0;
    while(block != NULL)
    {
        length += block->dataLength;
        block = block->next;
    }
    
    // 第一字节，0表示origin，1表示response
        fwrite(&direction, sizeof(char), 1, fp);
    
    // 接下来是一个整型变量，表示content长度
    fwrite(&length, sizeof(unsigned int), 1, fp);
    
    block = l->head;
    while(block != NULL)
    {
        // 接下来是content
        fwrite(block->data, sizeof(char), block->dataLength, fp);
        
        block = block->next;
    }
    
    flow_num++;
}

void cleanup()
{
	std::map<Connection *, bool>::const_iterator it = connMap.begin();
    while(it != connMap.end())
    {
        Connection * conn = (*it).first;
        
        writeToFile(combined_file, 0, &(conn->origList));
        writeToFile(combined_file, 1, &(conn->respList));
        memPool.release(&(conn->origList));
        memPool.release(&(conn->respList));
        conn->origList.empty();
        conn->respList.empty();
        
        it++;
    }
}

void tcp_callback(struct tcp_stream *a_tcp, void ** param)
{
    if (a_tcp->nids_state == NIDS_JUST_EST)
    {
		// connection described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		a_tcp->client.collect++; // we want data received by a client
		a_tcp->server.collect++; // and by a server, too
		
		Connection * conn = connPool.getObject();
		*param = conn;
		connMap[conn] = true;
		
		conn_num++;
		
		return;
    }
	else if (a_tcp->nids_state == NIDS_RESET || a_tcp->nids_state == NIDS_CLOSE)
    {
        Connection * conn = (Connection *)(*param);
        writeToFile(combined_file, 0, &(conn->origList));
        writeToFile(combined_file, 1, &(conn->respList));
        memPool.release(&(conn->origList));
        memPool.release(&(conn->respList));
        conn->origList.empty();
        conn->respList.empty();
        
        connMap.erase(conn);
		return;
    }
	else if (a_tcp->nids_state == NIDS_DATA)
    {
        Connection * conn = (Connection *)(*param);
        
        // original
		if (a_tcp->server.count_new > 0)
        {
            struct half_stream * hlf = &a_tcp->server;
            
            if(hlf->count_new > 0)
            {
                app_bytes += hlf->count_new;
                // printf("%d\n", hlf->count_new);
                
                addToList(hlf->data, hlf->count_new, &(conn->origList));
            }
        }
        
        // response
        if (a_tcp->client.count_new > 0)
        {
            struct half_stream * hlf = &a_tcp->client;
            
            if(hlf->count_new > 0)
            {
                app_bytes += hlf->count_new;
                // printf("%d\n", hlf->count_new);
                
                addToList(hlf->data, hlf->count_new, &(conn->respList));
            }
        }
        
        return;
    }
}

int main(int argc, char *argv[])
{
    struct timeval startTime;
    struct timeval endTime;
    struct timeval diffTime;
    
    gettimeofday(&startTime, NULL);
    
	if(argc <= 1)
	{
		printf("Usage: %s <input trace file> <output file>.\n", argv[0]);
		return 0;
	}
	
	nids_params.filename = argv[1];
	
	combined_file = fopen(argv[2], "rb");
	if(combined_file != NULL)
	{
	    fprintf(stderr, "Output file %s has existed, please use another name.\n", argv[2]);
	    exit(0);
	}
	
	combined_file = fopen(argv[2], "wb");
	if(combined_file == NULL)
	{
	    fprintf(stderr, "Cannot create file %s.\n", argv[2]);
	    exit(0);
	}
	
	if (!nids_init())
    {
        printf("%s\n", nids_errbuf);
        exit(1);
    }
	
    nids_register_tcp((void *)tcp_callback);
    nids_run();
    
    if(combined_file != NULL)
    {
        cleanup();
        fclose(combined_file);
        combined_file = NULL;
    }
    
    gettimeofday(&endTime, NULL);
	TIMERSUB(&endTime, &startTime, &diffTime);
	
	printf("conn_num = %d\n", conn_num);
	printf("flow_num = %d\n", flow_num);
    printf("app_bytes = %d\n", app_bytes);
    printf("time = %lu.%lu s\n", (unsigned long)diffTime.tv_sec, (unsigned long)diffTime.tv_usec);
    
    char * logFilePath = new char[strlen(argv[2]) + 5];
    sprintf(logFilePath, "%s.log", argv[2]);
    FILE * logFile = fopen(logFilePath, "w");
    fprintf(logFile, "conn_num = %d\n", conn_num);
	fprintf(logFile, "flow_num = %d\n", flow_num);
    fprintf(logFile, "app_bytes = %d\n", app_bytes);
    fprintf(logFile, "time = %lu.%lu s\n", (unsigned long)diffTime.tv_sec, (unsigned long)diffTime.tv_usec);
    fclose(logFile);
	
	return 0;
}
