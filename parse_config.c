#include "parse_config.h"
#include "ini.h"
#include <string.h>
#include <stdlib.h>

#define ENTRY_BUF_SIZE 30

static int32_t count_blacklist_entries(const char *str) 
{
    int count = 0;
    for (int i = 0; str[i] != '\0'; i++) 
    {
        if (str[i] == ',') 
            count++;
    }
    return count + 1;
}

#define STRING_MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

static int32_t handler(void* user, const char* section, const char* name, const char* value)
{
    config_t *pconf = (config_t*)user;
    if (STRING_MATCH("config", "upstream"))
        strcpy(pconf->upstream_ip, value);
    if (STRING_MATCH("config", "response"))
    {
        char *resp = strdup(value);
        if (strcmp(resp, "notfound") == 0)
            pconf->resp_t = RESP_NOTFOUND;
        else if (strcmp(resp, "refused") == 0)
            pconf->resp_t = RESP_REFUSED;
        else if (strcmp(resp, "fakeip"))
            pconf->resp_t = RESP_FAKEIP;
        else 
            pconf->resp_t = RESP_UNKNOWN;
        free(resp);
    }
    if (STRING_MATCH("config", "fake_ip"))
        strcpy(pconf->fake_ip, value);
    if (STRING_MATCH("config", "blacklist"))
    {
        char *list = strdup(value);
        int32_t entries = count_blacklist_entries(list);
        pconf->blacklist_count = entries;
        pconf->blacklist = (char**)malloc(pconf->blacklist_count * sizeof(char*));
        for (int32_t i = 0; i < pconf->blacklist_count; ++i)
            pconf->blacklist[i] = (char*)calloc(ENTRY_BUF_SIZE, sizeof(char));
        
        // Adding entries to array
        int32_t entry_count = 0;
        for (char *entry = strtok(list, ","); entry != NULL && entry_count != entries; 
            entry = strtok(NULL, ",")
        )
        {
            strcpy(pconf->blacklist[entry_count++], entry);
        }

        free(list);
    }   
    return 1;
}

int32_t load_proxy_config(const char *fname, config_t *conf)
{
    if (ini_parse(fname, handler, (void*)conf) < 0)
        return -1;

    return 0;
}