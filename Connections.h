
#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <string>
#include <cstdint> 

#include "Shim.h"

#define IPV4_CLASS_A_MIN  0x0A000000    // Class A range 10.0.0.0/8.
#define IPV4_CLASS_A_MASK 0xFF000000    // Class A netmask 255.0.0.0.
#define IPV4_CLASS_B_MIN  0xAC100000    // Class B min range 172.16.0.0/12.
#define IPV4_CLASS_B_MAX  0xAC1F0000    // Class B max range 172.31.0.0/12.
#define IPV4_CLASS_B_MASK 0xFFF00000    // Class B netmask 255.240.0.0.
#define IPV4_CLASS_C_MIN  0xC0A80000    // Class C range 192.168.0.0/16.
#define IPV4_CLASS_C_MASK 0xFFFF0000    // Class C netmask 255.255.0.0.
#define IPV4_LOCAL_MIN    0x7F000000    // Local range 127.0.0.0/8.
#define IPV4_LOCAL_MASK   0xFF000000    // Local netmask 255.0.0.0.

using Shim::IPV4_PACKET;

namespace Connections
{
    // Describes type of local packet match.
    enum MATCH_TYPE
    {
        MATCH,
        NO_MATCH,
        REVERSE_MATCH
    };

    // Check if packet is part of a local connection.
    MATCH_TYPE isPacketLocal(IPV4_PACKET);

    // Connection object built from packets.
    class Connection
    {
        public:
            std::string srcIP;    // Connection local ip address.
            std::string dstIP;    // Connection remote ip address.
            std::string protocol; // Connection protocol (tcp, udp).
            std::string state;    // One or two way direction of transmission.
            uint16_t srcPort;     // Connection protocol source port.
            uint16_t dstPort;     // Connection protocol destination port.
            uint64_t packetCount; // all packets sent.
            uint64_t dataSent;    // total of all data in payloads sent.

            // Constructor automatically converts Shim packet to conn object.
            Connection(IPV4_PACKET);

            // Match connection objects.
            MATCH_TYPE MatchConnection(Connection);
    };

    //Check if ip is in private class range
    inline bool IPV4AddrIsLocal(const in_addr &ipAddr)
    {
        //Binary compare for netork range
        if ((ntohl(ipAddr.s_addr) & IPV4_CLASS_A_MASK) == IPV4_CLASS_A_MIN)
            return true;
        else if (((ntohl(ipAddr.s_addr) & IPV4_CLASS_B_MASK) >= IPV4_CLASS_B_MIN)
                 && ((ntohl(ipAddr.s_addr) & IPV4_CLASS_B_MASK) <= IPV4_CLASS_B_MAX))
            return true;
        else if ((ntohl(ipAddr.s_addr) & IPV4_CLASS_C_MASK) == IPV4_CLASS_C_MIN)
            return true;
        else if ((ntohl(ipAddr.s_addr) & IPV4_LOCAL_MASK) == IPV4_LOCAL_MIN)
            return true;
        
        return false;
    }
}

#endif
