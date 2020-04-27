
#include <cstdint>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "Connections.h"
#include "Packets.h"
#include "Shim.h"

using Connections::Connection;
using Connections::isPacketLocal;
using Connections::MATCH_TYPE;
using Connections::MATCH;
using Connections::NO_MATCH;
using Connections::REVERSE_MATCH;

using Packets::IPV4AddrToStr;
using Packets::IPV4AddrIsLocal;

using Shim::IPV4_PACKET;
using Shim::TCP;

Connection::Connection(IPV4_PACKET packet)
{
	// Set protocol.
	if (packet.protocol == TCP)
		protocol = "TCP";
	else
		protocol = "UDP";

	// Set IPs and ports (flip if reverse local)
	if (isPacketLocal(packet) != REVERSE_MATCH)
	{
		state = "->";
		srcIP = IPV4AddrToStr(packet.source_address);
		dstIP = IPV4AddrToStr(packet.destination_address);
		srcPort = packet.source_port;
		dstPort = packet.destination_port;
	}
	else
	{
	    state = "<-";
		srcIP = IPV4AddrToStr(packet.destination_address);
		dstIP = IPV4AddrToStr(packet.source_address);
		srcPort = packet.destination_port;
		dstPort = packet.source_port;
	}

	// Set packet count.
	packetCount = 1;
	// Set data sent.
	dataSent = packet.payload_size;
}

MATCH_TYPE Connection::MatchConnection(Connection conn)
{
	// Check for match.
	if (((srcIP == conn.srcIP) && (dstIP == conn.dstIP))
		&& ((srcPort == conn.srcPort) && (dstPort == conn.dstPort)))
		return MATCH;
	// Check for reverse match.
	else if (((srcIP == conn.dstIP) && (dstIP == conn.srcIP))
		     && ((srcPort == conn.dstPort) && (dstPort == conn.srcPort)))
		return REVERSE_MATCH;

	return NO_MATCH;
}

MATCH_TYPE Connections::isPacketLocal(IPV4_PACKET packet)
{
	// Check for local dest without local source.
	if ((IPV4AddrIsLocal(packet.destination_address))
		&& (!IPV4AddrIsLocal(packet.source_address)))
		return REVERSE_MATCH;
	// Check for local sorce or local sorce and local dest.
	else if (IPV4AddrIsLocal(packet.source_address))
		return MATCH;

	return NO_MATCH;
}
