#include "dns.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define set_bit(num, pos)  (num | (1 << (pos - 1)));
#define zero_bit(num, pos) (num & (~(1 << (pos - 1))));


void init_dns_connection(dns_connection *conn, const char *addr, int32_t port)
{
    conn->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    conn->conn_s.sin_family = AF_INET;
    conn->conn_s.sin_addr.s_addr = inet_addr(addr);
    conn->conn_s.sin_port = htons(port);
    connect(conn->socket, (struct sockaddr*)&conn->conn_s, sizeof(conn->conn_s));
}

void build_dns_header(dns_header *dhd)
{
    dhd->id = htons(0xAAAA);
    dhd->flags = set_bit(dhd->flags, 9); // RD
    dhd->flags = htons(dhd->flags);
    dhd->qdcount = htons(1);
}

dns_request *build_dns_request(const char *request_string, dns_header *hdr, int32_t *dns_len)
{
    if (!request_string || !hdr)
        return NULL;

    char req_copy[256];
    strncpy(req_copy, request_string, sizeof(req_copy));
    req_copy[sizeof(req_copy) - 1] = 0;

    // calculating QNAME length
    int32_t qname_len = 0;
    char *token;

    token = strtok(req_copy, ".");
    while (token) 
    {
        qname_len += strlen(token) + 1;
        token = strtok(NULL, ".");
    }
    qname_len += 1; // null terminator

    int32_t request_len = sizeof(dns_header) + qname_len + 2 * sizeof(uint16_t);
    dns_request *req = (dns_request*)malloc(sizeof(dns_request) + request_len * sizeof(char));
    if (!req) return NULL;

    req->header = *hdr;

    // forming QNAME
    strncpy(req_copy, request_string, sizeof(req_copy));
    req_copy[sizeof(req_copy) - 1] = 0;

    int32_t offset = 0;
    token = strtok(req_copy, ".");
    while (token) {
        uint8_t len = strlen(token);
        req->body[offset] = len;
        memcpy(req->body + offset + 1, token, len);
        offset += len + 1;
        token = strtok(NULL, ".");
    }
    req->body[offset] = 0; // null terminator

    // QTYPE and QCLASS
    uint16_t qtype = htons(1);  // A
    uint16_t qclass = htons(1); // IN
    memcpy(req->body + qname_len, &qtype, sizeof(uint16_t));
    memcpy(req->body + qname_len + sizeof(uint16_t), &qclass, sizeof(uint16_t));

    *dns_len = request_len;
    return req;
}

char *perform_dns_request(dns_connection *conn, dns_request *req, int32_t dns_len)
{
    if (!conn || !req)
        return NULL;

    sendto(
        conn->socket, (const char*)req, dns_len,
        0, (struct sockaddr*)&conn->conn_s, sizeof(conn->conn_s)
    );

    char *recvbuf = (char*)malloc(RECV_BUF_SIZE * sizeof(char));
    if (!recvbuf) return NULL;
    int32_t conn_size = sizeof(conn->conn_s);
    int32_t received_bytes = recvfrom(
        conn->socket, recvbuf, RECV_BUF_SIZE, 
        0, (struct sockaddr*)&conn->conn_s, &conn_size
    );
    recvbuf[received_bytes] = 0;
    return recvbuf;
}

char **parse_dns_request(char *bytes, int32_t *count)
{
    if (!bytes)
        return NULL;

    uint8_t *ptr = (uint8_t*)bytes;

    uint16_t qdcount = ntohs(*(uint16_t*)(ptr + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(ptr + 6));

    int32_t offset = 12;

    for (int32_t i = 0; i < qdcount; i++) 
    {
        while (ptr[offset] != 0) offset += ptr[offset] + 1;
        offset += 1; // null terminator
        offset += 4; // QTYPE + QCLASS
    }

    char **list = (char**)malloc(ancount * sizeof(char*));
    int32_t arr_iter = 0;

    for (int32_t i = 0; i < ancount; i++) 
    {
        // NAME
        if ((ptr[offset] & 0xC0) == 0xC0)
            offset += 2;
        else 
        {
            while (ptr[offset] != 0) offset += ptr[offset] + 1;
            offset += 1;
        }

        uint16_t type = ntohs(*(uint16_t*)(ptr + offset)); offset += 2;
        uint16_t tclass = ntohs(*(uint16_t*)(ptr + offset)); offset += 2;
        uint32_t ttl = ntohl(*(uint32_t*)(ptr + offset)); offset += 4;
        uint16_t rdlen = ntohs(*(uint16_t*)(ptr + offset)); offset += 2;

        char buffer[INET_ADDRSTRLEN + 128]; 

        if (type == 1 && tclass == 1 && rdlen == 4) // A
        {
            inet_ntop(AF_INET, ptr + offset, buffer, sizeof(buffer));
            list[arr_iter] = strdup(buffer);
        }
        else if (type == 28 && tclass == 1 && rdlen == 16) // AAAA
        {
            inet_ntop(AF_INET6, ptr + offset, buffer, sizeof(buffer));
            list[arr_iter] = strdup(buffer);
        }
        else if (type == 5) // CNAME
        {
            // decoding QNAME from RDATA
            int rdoffset = 0;
            int pos = 0;
            while (rdoffset < rdlen) 
            {
                uint8_t len = ptr[offset + rdoffset];
                if (len == 0) break;
                if ((len & 0xC0) == 0xC0) // reference
                {
                    rdoffset += 2;
                    break;
                }
                rdoffset += len + 1;
            }
            snprintf(buffer, sizeof(buffer), "CNAME (len=%d)", rdlen);
            list[arr_iter] = strdup(buffer);
        }
        else
        {
            snprintf(buffer, sizeof(buffer), "TYPE=%d CLASS=%d LEN=%d", type, tclass, rdlen);
            list[arr_iter] = strdup(buffer);
        }

        arr_iter++;
        offset += rdlen;
    }

    *count = arr_iter;
    return list;
}
