#ifndef _TCP_REASSEMBLER_H_
#define _TCP_REASSEMBLER_H_

#include "stdio.h"
#include "stdlib.h"

#ifndef NULL
#define NULL 0
#endif

#ifndef verify
#define verify(code) if(!(code)) { fprintf(stderr, "Runtime error: %s:%d\n", __FILE__, __LINE__); exit(0); }
#endif

#endif
