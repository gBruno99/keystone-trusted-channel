#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include <string.h>
#include "printf.h"
// #include <stdio.h>

typedef struct {
  int fd;
  int retval;
} net_connect_t;

void initialize_execution_time(struct execution_time *data) {
    data->start.tv_nsec = -1;
    data->start.tv_sec = -1;
    data->end.tv_nsec = -1;
    data->end.tv_sec = -1;
    data->total = -1;

    return ;
}

void send_data_to_host(unsigned char *data, size_t len) {
    ocall(OCALL_SEND_DATA, data, len, NULL, 0);
    return;
}
void custom_net_init(mbedtls_net_context *ctx) {
    ctx->fd = -1;
}

/* ocall to open internet connection */
int custom_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto) {
    int ret;
    net_connect_t retval;
    ret = ocall(OCALL_NET_CONNECT, NULL, 0,(void*) &retval, sizeof(net_connect_t));
    ret |= retval.retval;
    // mbedtls_printf("net_connect - fd: %d, ret: %d\n", retval.fd, retval.retval);
    if(ret) {
        return ret;
    } else {
        ctx->fd = retval.fd;
    }
    return 0;
}

/* ocall to send internet packets */
int custom_net_send(void *ctx, const unsigned char *buf, size_t len) {
    
    int ret, retval;
    unsigned  char tmp_buf[2048+sizeof(int)];
    if(len > 2048)
        return -1;
    int *fd = (int*) tmp_buf;
    *fd = ((mbedtls_net_context *) ctx)->fd;
    memcpy(tmp_buf+sizeof(int), buf, len);
#if 1
    struct execution_time data;
    initialize_execution_time(&data);
    custom_clock_gettime((void *)&data.start);
    ret = ocall(OCALL_NET_SEND, (unsigned char *)tmp_buf, len+sizeof(int), &retval, sizeof(int));
    custom_clock_gettime((void *)&data.end);
    data.total = data.end.tv_nsec - data.start.tv_nsec;
    data.which_ocall = SEND;
    if (data.total > 0) {
        // legit value
       custom_printf("OCALL NET SEND = %ld ms for %lu bytes\n", (long)(data.total / 1000000), len);
    //    send_data_to_host((unsigned char *)&data, sizeof(struct execution_time));
    }
#else
    ret = ocall(OCALL_NET_SEND, (unsigned char *)tmp_buf, len+sizeof(int), &retval, sizeof(int));
#endif

    
    return ret|retval;
}

/* ocall to receive internet packets */
int custom_net_recv(void *ctx, unsigned char *buf, size_t len) {
    int ret;
    unsigned char tmp_buf[16896+sizeof(int)];
    int *fd = (int*) tmp_buf;
    *fd = ((mbedtls_net_context *) ctx)->fd;
#if 1
    struct execution_time data;
    initialize_execution_time(&data);
    custom_clock_gettime((void *)&data.start);
    ret = ocall(OCALL_NET_RECV, tmp_buf, len, tmp_buf, len + sizeof(int));
    custom_clock_gettime((void *)&data.end);
    data.total = data.end.tv_nsec - data.start.tv_nsec;
    data.which_ocall = RECV;
    if (data.total > 0) {
        // legit value
        custom_printf("OCALL NET SEND = %ld ms for %lu bytes\n", (long)(data.total / 1000000), len);
        // send_data_to_host((unsigned char *)&data, sizeof(struct execution_time));

    }
#else 
    ret = ocall(OCALL_NET_RECV, tmp_buf, len, tmp_buf, len + sizeof(int));
#endif
    // printf("ocall returned %d\n", ret);
    int retval = * ((int*)tmp_buf);
    memcpy(buf, tmp_buf+sizeof(int), len);
    // printf("Asked for %lu bytes, received %d: %s\n", len, retval, tmp_buf+sizeof(int));
    // fflush(stdout);
    return ret|retval;
}

void custom_net_free(mbedtls_net_context *ctx) {
    int fd = ((mbedtls_net_context *) ctx)->fd;
    ocall(OCALL_NET_FREE, (unsigned char *) &fd, sizeof(int), NULL, 0);
}
