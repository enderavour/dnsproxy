#include "dns.h"
#include "parse_config.h"
#include "blacklist.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static config_t CONFIG = {0};

int32_t main(int argc, char *argv[])
{
    load_proxy_config("config.ini", &CONFIG);

    int32_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(53);

    bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    uint8_t buf[1024], resp[1024];
    struct sockaddr_in client;
    int32_t len = sizeof(client);

    printf("DNS proxy running...\n");

    while (1)
    {
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&client, &len);
        if (n <= 0) continue;

        char domain[256];
        extract_qname(buf, domain, sizeof(domain));

        if (is_blacklisted(&CONFIG, domain))
        {
            int resp_len = build_blacklist_response(buf, n, &CONFIG, resp);
            sendto(sock, resp, resp_len, 0, (struct sockaddr*)&client, len);
        }
        else
        {
            dns_connection upstream;
            init_dns_connection(&upstream, CONFIG.upstream_ip, 53);
            char *up_resp = perform_dns_request(&upstream, (dns_request*)buf, n);
            if (up_resp)
            {
                sendto(sock, up_resp, RECV_BUF_SIZE, 0, (struct sockaddr*)&client, len);
                free(up_resp);
            }
            close(upstream.socket);
        }
    }

    for (int i = 0; i < CONFIG.blacklist_count; ++i)
    {
        free(CONFIG.blacklist[i]);
    }

    free(CONFIG.blacklist);


    return 0;
}
