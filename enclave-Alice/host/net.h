#ifndef _HOST_NET_H_
#define _HOST_NET_H_

struct execution_time {
    struct timespec start;
    struct timespec end;
    long total;
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
send_data_wrapper(void *buffer);
#endif
