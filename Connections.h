
#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <string>
#include <cstdint> 

#include "Shim.h"

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
}

#endif
