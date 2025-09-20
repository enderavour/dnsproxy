# DNS Proxy with Blacklist and Fake IP Support

## Description
This is a simple DNS proxy server that intercepts DNS requests and checks them against a domain blacklist.

Features:

- Reads configuration from config.ini file.
- Supports a blacklist of domains.
- Allows configuring the type of response for blacklisted domains:
  - `notfound` — returns "non-existent domain".
  - `refused` — returns "query refused".
  - `fakeip` — returns a pre-configured IP address.
- Forwards allowed requests to an upstream DNS server (e.g., 1.1.1.1 or 8.8.8.8).
- Works over UDP protocol.
- Supports IPv4 and partially IPv6 (CNAME, AAAA).

---

## Installation and Compilation

### Linux 
```bash
make
```
## Execute 

Enter the root user and perform 
```bash
./dproxy config.ini
```

After the server is running, it will check if given domain name is blocked or not, and \
forward the IP or return response which is provided in configuration file.

## How to check?
Check of working can be done in two ways:
```bash 
dig @127.0.0.1 evil.net
```
or 
```
nslookup bad.com 127.0.0.1
```

## Configuration file

This server uses .ini format of files.

Provided configuration file sample has format:
```bash
[config]
upstream=1.1.1.1
blacklist=bad.com,evil.net
response=refused
fake_ip=192.0.2.123
```
Where:
```upstream``` - DNS server address (CloudFlare by default)
```blacklist``` - sequence of restricted domain names
```response``` - type of server response. May hold next values: ```notfound```, ```refused```, ```fakeip```

```fake_ip``` - IP address to which query will be resolved in case of ```fakeip``` parameter.

## Notes 
Configuration file parsing was implemented using "inih" library, which consists of ini.h and ini.c files \ in my project: \
[Github Repository](https://github.com/benhoyt/inih.git)