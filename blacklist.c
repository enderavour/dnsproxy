#include "blacklist.h"
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void extract_qname(const uint8_t *req, char *out, int out_size)
{
    int32_t offset = 12;
    int i = 0;

    while (req[offset] != 0 && i < out_size - 1)
    {
        int32_t len = req[offset++];
        for (int j = 0; j < len && i < out_size - 1; j++)
            out[i++] = req[offset++];
        if (req[offset] != 0) out[i++] = '.';
    }
    out[i] = 0;
}

int is_blacklisted(config_t *conf, const char *domain)
{
    for (int i = 0; i < conf->blacklist_count; i++)
    {
        if (strcmp(domain, conf->blacklist[i]) == 0)
            return 1;
    }
    return 0;
}

int build_blacklist_response(uint8_t *request, int req_len, config_t *conf, uint8_t *resp)
{
    memcpy(resp, request, req_len); 
    uint16_t *flags = (uint16_t*)(resp + 2);
    *flags = ntohs(*flags);

    *flags &= 0xFFF0; // обнуляем RCODE
    if (conf->resp_t == RESP_NOTFOUND) *flags |= 3;  // NXDOMAIN
    else if (conf->resp_t == RESP_REFUSED) *flags |= 5; // REFUSED

    *flags = htons(*flags);

    if (conf->resp_t == RESP_FAKEIP)
    {
        uint16_t *ancount = (uint16_t*)(resp + 6);
        *ancount = htons(1); // 1 answer

        int offset = req_len;

        // copying QNAME from query
        int qname_len = 0;
        while (request[12 + qname_len] != 0) qname_len++;
        qname_len++; // null
        memcpy(resp + offset, request + 12, qname_len);
        offset += qname_len;

        uint16_t type = htons(1), class = htons(1);
        memcpy(resp + offset, &type, 2); offset += 2;
        memcpy(resp + offset, &class, 2); offset += 2;

        uint32_t ttl = htonl(3600);
        memcpy(resp + offset, &ttl, 4); offset += 4;

        uint16_t rdlen = htons(4);
        memcpy(resp + offset, &rdlen, 2); offset += 2;

        struct in_addr fake;
        inet_pton(AF_INET, conf->fake_ip, &fake);
        memcpy(resp + offset, &fake, 4); offset += 4;

        return offset;
    }

    return req_len;
}
