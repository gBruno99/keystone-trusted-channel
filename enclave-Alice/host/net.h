#ifndef _HOST_NET_H_
#define _HOST_NET_H_

/*flags for execution time data*/
#define OPEN 0
#define SEND 1
#define RECV 2 
#define CLOSE 3

struct execution_time {
    struct timespec start;
    struct timespec end;
    long total;
    int which_ocall;
};

void
net_connect_wrapper(void* buffer);
void
net_send_wrapper(void* buffer);
void
net_recv_wrapper(void* buffer);
void
net_free_wrapper(void* buffer);
void
send_data_to_host_wrapper(void *buffer);


#endif
