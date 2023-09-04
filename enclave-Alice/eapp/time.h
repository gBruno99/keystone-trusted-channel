#include "eapp/eapp_net.h"
#include "app/syscall.h"
#include <string.h>

#define CLOCK_FREQUENCY 10 /* MHz */

typedef struct {
    int count;
    double ticks; /*clock ticks*/
    double msec; /*milliseconds*/
} execution_time_t;

void send_execution_time_data(void *data);
