#ifndef _EAPP_NET_H_
#define _EAPP_NET_H_

#define OCALL_NET_CONNECT 1
#define OCALL_NET_SEND    2
#define OCALL_NET_RECV    3
#define OCALL_NET_FREE    4
#define OCALL_SEND_DATA   7


/*flags for execution time data*/
#define OPEN 0
#define SEND 1
#define RECV 2 
#define CLOSE 3


#include "mbedtls/net_sockets.h"

typedef long time_t;
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct execution_time {
    struct timespec start;
    struct timespec end;
    long total;
    int which_ocall;
};

void custom_net_init(mbedtls_net_context *ctx);
int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);
int custom_net_send(void *ctx, const unsigned char *buf, size_t len);
int custom_net_recv(void *ctx, unsigned char *buf, size_t len);
void custom_net_free(mbedtls_net_context *ctx);
void send_data_to_host(unsigned char *data, size_t len);
void initialize_execution_time(struct execution_time *data);
#endif