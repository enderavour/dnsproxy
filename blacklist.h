#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <stdint.h>
#include "parse_config.h"

void extract_qname(const uint8_t *req, char *out, int out_size);
int is_blacklisted(config_t *conf, const char *domain);
int build_blacklist_response(uint8_t *request, int req_len, config_t *conf, uint8_t *resp);

#endif