#include "time.h"
#include "eapp/eapp_net.h"

void send_execution_time_data(void *data) {
    ocall(OCALL_NET_SEND, (unsigned char *)&data, sizeof(execution_time_t), NULL, 0); // we don't need return data
    return;
}