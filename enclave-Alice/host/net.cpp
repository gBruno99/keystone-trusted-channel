#include "mbedtls/net_sockets.h"
#include "edge/edge_call.h"
#include "host/keystone.h"
#include "net.h"
#include <stdio.h>
#include <time.h>

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
struct execution_time time_open_host, time_send_host, time_recv_host, time_close_host;
typedef struct {
  int fd;
  int retval;
} net_connect_t;

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
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_open_host.start);
  /* Pass the arguments from the eapp to the exported ocall function */
  ret_val = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);

  net_connect_t ret;
  ret.fd = server_fd.fd;
  ret.retval = ret_val;

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret, sizeof(net_connect_t));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(net_connect_t))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_open_host.end);
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
  ret_val = mbedtls_net_send(&server_fd, (unsigned char *) call_args+sizeof(int), arg_len-sizeof(int));

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
    ret_val = mbedtls_net_recv(&server_fd, recv_buffer+sizeof(int), arg_len);
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
  mbedtls_net_free(&server_fd);
  ret_val = 0;

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
  long time_communication_enclave_host = performance_data->total - time_open_host.total;
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