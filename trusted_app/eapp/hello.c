/*
 *  SSL client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "app/eapp_utils.h"
#include "edge/edge_call.h"
#include "app/syscall.h"
#include "app/malloc.h"

#include "eapp/eapp_net.h"
#include "eapp/eapp_crt.h"

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "certs.h"
#include "printf.h"
#include "custom_functions.h"

// #include <stdio.h>
// #include <time.h>
#include <string.h>

#define PUBLIC_KEY_SIZE     32
#define PRIVATE_KEY_SIZE    64
#define PARSE_PUBLIC_KEY    0
#define PARSE_PRIVATE_KEY   1
#define CERTS_MAX_LEN       512
#define CSR_SIZE            2048
#define HASH_LEN            64
#define SIG_LEN             64
#define NONCE_LEN           32
#define MDSIZE              64
#define SIGNATURE_SIZE      64
#define ATTEST_DATA_MAXLEN  1024
#define PRINT_STRUCTS 0

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define GET_NONCE_REQUEST "GET /nonce HTTP/1.0\r\n\r\n"

#define POST_CSR_REQUEST_START \
    "POST /csr/size HTTP/1.0\r\nContent-Type: application/json\r\n\r\n" \
    "{\"csr_len\": %d, \"csr\": \"0x" 

#define POST_CSR_REQUEST_END \
    "\"}\r\n"

#define HTTP_NONCE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"nonce\": \"0x" 

#define HTTP_NONCE_RESPONSE_END \
    "\"}\r\n"

#define HTTP_CERTIFICATE_SIZE_RESPONSE_START \
    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" \
    "{\"crt_len\": " 

#define HTTP_CERTIFICATE_SIZE_RESPONSE_END \
    ", "

#define HTTP_CERTIFICATE_RESPONSE_START \
    "\"crt\": \"0x" 

#define HTTP_CERTIFICATE_RESPONSE_END \
    "\"}\r\n"


#define DEBUG_LEVEL 1

typedef unsigned char byte;

struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};


int get_crt(unsigned char *buf, unsigned char *crt, int *len);

void custom_exit(int status);

int main(void)
{
    custom_printf("Hello from the trusted application.\n");
    custom_exit(0);
}

void custom_exit(int status){
    EAPP_RETURN(status);
}

int get_crt(unsigned char *buf, unsigned char *crt, int *len) {
    int i = 0, j = 0, tmp_len = 0;
    unsigned char start_len[] = HTTP_CERTIFICATE_SIZE_RESPONSE_START;
    unsigned char end_len[] = HTTP_CERTIFICATE_SIZE_RESPONSE_END;
    for(i=0; i<sizeof(HTTP_CERTIFICATE_SIZE_RESPONSE_START)-1; i++){
        if(buf[i] != start_len[i])
            return -1;
    }
    while(buf[i] >= '0' && buf[i] <= '9'){
        tmp_len *= 10;
        tmp_len += buf[i] - '0';
        i++;
    }
    for(j = i; j < i+sizeof(HTTP_CERTIFICATE_SIZE_RESPONSE_END)-1; j++){
        if(buf[j]!=end_len[j-i])
            return -1;
    }
    *len = tmp_len;
    if(memcmp(buf+j, HTTP_CERTIFICATE_RESPONSE_START, sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1)!=0) {
        mbedtls_printf("[C] cannot read certificate\n\n");
        return -1;
    }
    memcpy(crt, buf+j+sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1, tmp_len);
    if(memcmp(buf+j+sizeof(HTTP_CERTIFICATE_RESPONSE_START)-1+tmp_len, 
            HTTP_CERTIFICATE_RESPONSE_END, sizeof(HTTP_CERTIFICATE_RESPONSE_END))!=0){
        mbedtls_printf("[C] cannot read certificate 2\n\n");
        return -1;
    }
    return 0;
}

