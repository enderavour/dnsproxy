#ifndef DNS_IMPL_H
#define DNS_IMPL_H

#define RECV_BUF_SIZE 1024

#include <stdint.h>
#include <WinSock2.h>

typedef struct 
{
    int socket;
    struct sockaddr_in conn_s;
} dns_connection;

typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;

typedef struct 
{
    dns_header header;
    char body[1]; // This field contains QNAME, QTYPE and QCLASS 
    // implemented via dynamic struct "hack"
} dns_request;

void init_dns_connection(dns_connection *conn, const char *addr, int32_t port);
void build_dns_header(dns_header *dhd);
dns_request *build_dns_request(const char *request_string, dns_header *hdr, int32_t *dns_len);
char *perform_dns_request(dns_connection *conn, dns_request *req, int32_t dns_len);
char **parse_dns_request(char *bytes, int32_t *count);

#endif