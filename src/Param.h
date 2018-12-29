#include "NetShield.h"

// 堆栈大小，单位是byte
#ifndef NS_THREAD_STACK_SIZE
#define NS_THREAD_STACK_SIZE 32 * 1024
#endif

#ifndef CONNECTION_POOL_INIT_SIZE
#ifdef DEBUG
#define CONNECTION_POOL_INIT_SIZE 1
#else
#define CONNECTION_POOL_INIT_SIZE 8192
#endif
#endif
