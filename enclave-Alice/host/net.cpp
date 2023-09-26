#include "mbedtls/net_sockets.h"
#include "edge/edge_call.h"
#include "host/keystone.h"
#include "net.h"
#include <stdio.h>
#include <time.h>
#include <bits/stdc++.h>
#include <sys/time.h>
#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"

#define RECV_BUFFER_SIZE 16896


#define TIME_OPEN_FILENAME "performance_open.txt"
#define TIME_SEND_FILENAME "performance_send.txt"
#define TIME_RECV_FILENAME "performance_recv.txt"
#define TIME_CLOSE_FILENAME "performance_close.txt"

// struct to measure the communication host - internet
// by receiving from enclave the ocall execution time we can extract the 
// duration of the communication enclave-host
using namespace std;
struct execution_time time_open_host, time_send_host, time_recv_host, time_free_host;
typedef struct {
  int fd;
  int retval;
} net_connect_t;

struct timeval timeval_start, timeval_end;
void
net_connect_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  int ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  mbedtls_net_context server_fd;
  mbedtls_net_init(&server_fd);
  gettimeofday(&timeval_start, NULL);
  clock_gettime(CLOCK_REALTIME, &time_open_host.start);
  /* Pass the arguments from the eapp to the exported ocall function */
  ret_val = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
  clock_gettime(CLOCK_REALTIME, &time_open_host.end);
  gettimeofday(&timeval_end, NULL);
  double time_taken;
  time_taken = (timeval_end.tv_sec - timeval_start.tv_sec) * 1e6;
  time_taken = (time_taken + (timeval_end.tv_usec - timeval_start.tv_usec)) * 1e-6;
  net_connect_t ret;
  ret.fd = server_fd.fd;
  ret.retval = ret_val;
  cout << "Time taken by host to open internet connection is : " << fixed << time_taken << setprecision(6);
  cout << " sec" << endl;
  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret, sizeof(net_connect_t));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(net_connect_t))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  time_open_host.total = (long)(time_open_host.end.tv_nsec - time_open_host.start.tv_nsec);
  /* This will now eventually return control to the enclave */
  return;
}

void
net_send_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  int ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  mbedtls_net_context server_fd;
  server_fd.fd = *((int*)call_args);
  
  /* Pass the arguments from the eapp to the exported ocall function */
  clock_gettime(CLOCK_REALTIME, &time_send_host.start);
  ret_val = mbedtls_net_send(&server_fd, (unsigned char *) call_args+sizeof(int), arg_len-sizeof(int));
  clock_gettime(CLOCK_REALTIME, &time_send_host.end);
  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, sizeof(int));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(int))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  /* This will now eventually return control to the enclave */
  time_send_host.total = time_send_host.end.tv_nsec - time_send_host.start.tv_nsec;
  return;
}

void
net_recv_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  int ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  unsigned char recv_buffer[RECV_BUFFER_SIZE+sizeof(int)] = {0};
  mbedtls_net_context server_fd;
  server_fd.fd = *((int*)call_args);

  if(arg_len > RECV_BUFFER_SIZE)
    ret_val = -1;
  else {
    clock_gettime(CLOCK_REALTIME, &time_recv_host.start);
    ret_val = mbedtls_net_recv(&server_fd, recv_buffer+sizeof(int), arg_len);
    clock_gettime(CLOCK_REALTIME, &time_recv_host.end);
  }
  if (ret_val != -1) {
    time_recv_host.total = time_recv_host.end.tv_nsec - time_recv_host.start.tv_nsec;
  }
  *((int*)recv_buffer) = ret_val;

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &recv_buffer, sizeof(int)+(ret_val>0?ret_val:0));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(int)+(ret_val>0?ret_val:0))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}

void
net_free_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  mbedtls_net_context server_fd;
  server_fd.fd = *((int*)call_args);
  clock_gettime(CLOCK_REALTIME, &time_free_host.start);
  mbedtls_net_free(&server_fd);
  clock_gettime(CLOCK_REALTIME, &time_free_host.end);
  ret_val = 0;
  time_free_host.total = time_free_host.end.tv_nsec - time_free_host.start.tv_nsec;

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, 0);
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, 0)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}

void 
send_data_to_host(void *buffer, size_t len) {
  struct execution_time *performance_data = (struct execution_time *)buffer;
  int flag = performance_data->which_ocall;
  long eh_time;
  switch (flag)
  {
  case OPEN:
    eh_time = performance_data->total - time_open_host.total;
    printf("\nHOST: total execution time for opening connection = %ld ms\n", (performance_data->total) / 1000000);
    printf("\nHOST: total execution time for opening connection (host - internet) = %ld ms\n", (time_open_host.total) / 1000000);
    printf("\nHOST: communication enclave-host (open) = %ld ns ( %ld ms) \n", eh_time, eh_time / 1000000);
    break;
  case SEND:
    eh_time = performance_data->total - time_send_host.total;
    printf("\nHOST: total execution time for sending network data = %ld ms\n", (performance_data->total) / 1000000);
    printf("\nHOST: total execution time for sending network data (host - internet) = %ld ms\n", (time_send_host.total) / 1000000);
    printf("\nHOST: communication enclave-host (send) = %ld ns ( %ld ms) \n", eh_time, eh_time / 1000000);
    break;
  case RECV:
    eh_time = performance_data->total - time_recv_host.total;
    printf("\nHOST: total execution time for receiving network data = %ld ms\n", (performance_data->total) / 1000000);
    printf("\nHOST: total execution time for receiving network data (host - internet) = %ld ms\n", (time_recv_host.total) / 1000000);
    printf("\nHOST: communication enclave-host (recv) = %ld ns ( %ld ms) \n", eh_time, eh_time / 1000000);
    break;
  case CLOSE:
    eh_time = performance_data->total - time_free_host.total;
    printf("\nHOST: total execution time for closing internet connection = %ld ms\n", (performance_data->total) / 1000000);
    printf("\nHOST: total execution time for closing internet connection (host - internet) = %ld ms\n", (time_free_host.total) / 1000000);
    printf("\nHOST: communication enclave-host (close) = %ld ns ( %ld ms) \n", eh_time, eh_time / 1000000);
    break;
  default:
    break;
  }
  

  return;
}

void
send_data_to_host_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  int ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  send_data_to_host((void *)call_args, edge_call->call_arg_size);
  /* This will now eventually return control to the enclave */
  return;
}