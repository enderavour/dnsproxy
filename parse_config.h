#ifndef PARSE_CONFIG_H
#define PARSE_CONFIG_H

#include <stdint.h>

typedef enum 
{
    RESP_NOTFOUND,
    RESP_REFUSED,
    RESP_FAKEIP,
    RESP_UNKNOWN
} response_type;

typedef struct 
{
    char upstream_ip[64];
    char **blacklist;
    int blacklist_count;
    response_type resp_t;
    char fake_ip[64]; // if RESP_FAKEIP
} config_t;

int32_t load_proxy_config(const char *fname, config_t *conf);

#endif