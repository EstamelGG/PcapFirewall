#include <ws2tcpip.h>
#include <ipv6address.h>

char* ipv6address::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;
    sockaddrlen = sizeof(struct sockaddr_in6);
    if(getnameinfo(sockaddr,
        sockaddrlen,
        address,
        addrlen,
        NULL,
        0,
        NI_NUMERICHOST) != 0) address = NULL;

    return address;
}
