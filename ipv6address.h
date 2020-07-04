#ifndef IPV6ADDRESS_H
#define IPV6ADDRESS_H
#define WPCAP
#define HAVE_REMOTE
#include <ws2tcpip.h>

struct ipv6address
{
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

public:
    char ip6str[128];

};

#endif // IPV6ADDRESS_H
