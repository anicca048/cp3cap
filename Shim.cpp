
#ifdef _MSC_VER

#include <WS2tcpip.h>
#include <WinSock2.h>

#else

#include <arpa/inet.h>
#include <netinet/in.h>

#endif

#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <sstream>

#include <pcap/pcap.h>

#include "Shim.h"
#include "Packets.h"

using Packets::IPHdrVer;
using Packets::IPHdrLen;
using Packets::TCPHdrLen;
using Packets::IPV4AddrToStr;
using Packets::IP_Header;
using Packets::TCP_Header;
using Packets::UDP_Header;
using Packets::Ethernet_Header;

using Shim::L4_PROTOCOL;
using Shim::TCP;
using Shim::UDP;
using Shim::IPV4_PACKET;
using Shim::CaptureEngine;
using Shim::strToCSTR;

int CaptureEngine::genDeviceList()
{
	// Pcap error message buffer with WinPcap overflow protection.
	char pcapErrorBuffer[PCAP_ERRBUF_SIZE * 4];

	// generate libpcap interface list.
	pcap_if_t *deviceList;      // Pcap interface struct for device list.
	pcap_if_t *device;          // Pcap device list proxy for loop code clarity.

	// Grab pcap device list and check for retrieval error.
	if (pcap_findalldevs(&deviceList, pcapErrorBuffer) == -1)
	{
		engineError = pcapErrorBuffer;
		return -1;
	}

	// Clear device name and description lists if already set.
	if (deviceNames.size() != 0)
	{
		deviceNames.clear();
		deviceDescriptions.clear();
	}

	// Create device name and description lists from pcap interface structs.
	for (device = deviceList; device != nullptr; device = device->next)
	{
		// Add device name.
		deviceNames.push_back(device->name);

		// Add device description /w address if either exist.
		if (device->description)
		{
			std::string descriptionStr = device->description;

			if (device->addresses && (device->addresses->addr->sa_family == AF_INET))
				descriptionStr += ("[ " + IPV4AddrToStr(device->addresses->addr) + " ]");

			deviceDescriptions.push_back(descriptionStr);
		}
		else
			deviceDescriptions.push_back("");
	}

	// Cleanup memory from pcap interface lookup.
	pcap_freealldevs(deviceList);
	return 0;
}

int CaptureEngine::startCapture(const int deviceIndex, std::string filterStr)
{ 
	// Make sure we don't open resources without closing them first.
	if (engineHandle)
	{
		engineError = "must stop capture before starting another capture";
		return -1;
	}

    // Pcap error message buffer with WinPcap overflow protection.
    char pcapErrorBuffer[PCAP_ERRBUF_SIZE * 4];

    // Convert C++ string to cstr and create pcap device name.
    size_t devNameSize = (deviceNames[deviceIndex].length() + 1);
	char* pcapDevice = new char[devNameSize];
	strToCSTR(deviceNames[deviceIndex], pcapDevice, devNameSize);

    bpf_u_int32 deviceNetwork;  // Pcap device network address for filter.
    bpf_u_int32 deviceNetmask;  // Pcap device netmask for filter.

    // Get network and netmask address for filter compilation.
    if (pcap_lookupnet(pcapDevice, &deviceNetwork, &deviceNetmask,
                       pcapErrorBuffer) == -1)
    {
        // Not a critical error, just set these values incase of error.
        deviceNetwork = 0;
        deviceNetmask = PCAP_NETMASK_UNKNOWN;
    }

    // Pcap loop settings.
    int packetCaptureLength = 1518;     // Packet byte capture limit.
    int readTimeOutMS = 755;            // Packet read timeout.
    int promiscMode = 1;                // Promiscuous mode toggle.

    // Create capture session handle.
    engineHandle = pcap_open_live(pcapDevice, packetCaptureLength, promiscMode,
		                          readTimeOutMS, pcapErrorBuffer);

	// Free memory.
	delete[] pcapDevice;

    // Ensure no errors occured opening session handle.
    if (!engineHandle)
    {
        engineError = pcapErrorBuffer;
        return -1;
    }

    // Device must have a supported data link layer type.
    engineDataLink = pcap_datalink(engineHandle);

    switch (engineDataLink)
    {
        // Ethernet.
        case DLT_EN10MB:
        {
            break;
        }
        // RAW IP.
        case DLT_RAW:
        {
            break;
        }
        // Unsupported.
        default:
        {
			engineError = "unsupported device datalink type";
            return -1;
        }
    }

    // Compile and set pcap capture filter (add user filter if exist).
    if (!filterStr.empty() && filterStr != "")
    	filterStr = ("(udp or tcp) and " + filterStr);
    else
    	filterStr = "(udp or tcp)";

    // Create Pcap filter.
    size_t filterStrSize = (filterStr.length() + 1);
    char* pcapFilter = new char[filterStrSize];
	strToCSTR(filterStr, pcapFilter, filterStrSize);

    // Compile pcap filter and check for error.
    if (pcap_compile(engineHandle, &engineFilter, pcapFilter,
		             deviceNetmask, deviceNetwork) == -1)
    {
        engineError = pcap_geterr(engineHandle);
		// Free memory.
		delete[] pcapFilter;
        return -1;
    }

	// Free memory.
	delete[] pcapFilter;

    // Bind pcap filter to session handle and check for error.
    if (pcap_setfilter(engineHandle, &engineFilter) == -1)
    {
        engineError = pcap_geterr(engineHandle);
        return -1;
    }

    return 0;
}

int CaptureEngine::startCapture(std::string deviceName, std::string filterStr)
{
	// Check for valid device name.
	int deviceIndex = -1;
	int deviceCount = static_cast<int>(deviceNames.size());

	for (int i = 0; i < deviceCount; i++)
	{
		if (deviceName == deviceNames[i])
		{
			// Device name found.
			deviceIndex = i;
			break;
		}
	}

	if (deviceIndex == -1)
	{
		engineError = "invalid device name";
		return -1;
	}

	return startCapture(deviceIndex, filterStr);
}

int CaptureEngine::getNextPacket(IPV4_PACKET& nextPacket)
{
	if (!engineHandle)
	{
		engineError = "must start capture before getting a packet";
		return -1;
	}

	// Get pcap packet and pcap packet header.
	pcap_pkthdr pktHeader;
	const u_char* packet = pcap_next(engineHandle, &pktHeader);

	if (!packet)
		return -1;

    // Offset for internet protocol after DL strip.
    unsigned int ipHdrOff = 0;

    const struct Ethernet_Header* eth_hdr = nullptr;    // Ethernet header ptr.
    const struct IP_Header* ip_hdr = nullptr;			// IP header ptr.
    const struct TCP_Header* tcp_hdr = nullptr; 		// TCP header ptr.
    const struct UDP_Header* udp_hdr = nullptr;			// UDP header ptr.

    uint8_t  ip_ver;            // IP version (4 or 6).
    uint16_t ip_hdr_size;       // IP header size.
    uint16_t tcp_hdr_size;      // TCP header size.

    // Determine offset for IP header based on datalink type.
    switch (engineDataLink)
    {
        // Ethernet.
        case DLT_EN10MB:
        {
            // Check for damaged ethernet packet.
            if (pktHeader.caplen < ETHERNET_HDR_SIZE)
                return -1;

            // Define ethernet header.
            eth_hdr = reinterpret_cast<const struct Ethernet_Header*>(packet);

            // Drop non IPv4 packets.
            if (ntohs(eth_hdr->ether_type) != ETHERNET_TYPE_IPV4)
                return -1;

            // Check for damaged IPV4 packet.
            if (pktHeader.caplen < (ETHERNET_HDR_SIZE + IPV4_HEADER_MIN_LEN))
                return -1;

            // Use ethernet header for ipheader offset.
            ipHdrOff = ETHERNET_HDR_SIZE;
            break;
        }
        // RAW IP.
        case DLT_RAW:
        {
            // Check for damaged IPV4 packet.
            if (pktHeader.caplen < IPV4_HEADER_MIN_LEN)
                return -1;

            // Raw ip has no offset for ip heaser.
            ipHdrOff = 0;
            break;
        }
    }

	// Create IP header and stats from ethernet or raw header.
    ip_hdr = reinterpret_cast<const struct IP_Header*>(packet + ipHdrOff);
    ip_hdr_size = IPHdrLen(ip_hdr);
    ip_ver = IPHdrVer(ip_hdr);

    // Drop non IPv4 (IPv6) packets.
    if (ip_ver != IP_TYPE_V4)
        return -1;

    // Drop packets with invalid IP Header size.
    if (ip_hdr_size < IPV4_HEADER_MIN_LEN)
        return -1;

    // Set shim packet ip address properties.
    nextPacket.source_address = ip_hdr->ip_src;
    nextPacket.destination_address = ip_hdr->ip_dst;

    // Drop packets of unsupported protocols, or compare to connections list.
	if (ip_hdr->ip_p == IPPROTO_TCP)
	{
		// Check for damaged tcp packet.
		if (pktHeader.caplen < (ipHdrOff + IPV4_HEADER_MIN_LEN
			                    + TCP_HEADER_MIN_LEN))
			return -1;

		// Define tcp header by offset.
		tcp_hdr = reinterpret_cast<const struct TCP_Header*>(packet + ipHdrOff
			                                                 + ip_hdr_size);
		tcp_hdr_size = TCPHdrLen(tcp_hdr);

		// Drop packets with invalid tcp header size.
		if (tcp_hdr_size < TCP_HEADER_MIN_LEN)
			return -1;

		// Set connection protocol.
		nextPacket.protocol = TCP;

		// Set connection ports.
		nextPacket.source_port = ntohs(tcp_hdr->th_sport);
		nextPacket.destination_port = ntohs(tcp_hdr->th_dport);

		// Compute tcp payload wihtout using tcp segment section / option feild.
		nextPacket.payload_size = (ntohs(ip_hdr->ip_len) - (ip_hdr_size
			                                                + tcp_hdr_size));
	}
	else if (ip_hdr->ip_p == IPPROTO_UDP)
	{
		// check for damaged udp packet.
		if (pktHeader.caplen < (ipHdrOff + IPV4_HEADER_MIN_LEN + UDP_HDR_SIZE))
			return -1;

		// Define udp header by offset.
		udp_hdr = reinterpret_cast<const struct UDP_Header*>(packet + ipHdrOff
			                                                 + ip_hdr_size);

		// Set connection protocol.
		nextPacket.protocol = UDP;

		// Set connection ports.
		nextPacket.source_port = ntohs(udp_hdr->uh_sport);
		nextPacket.destination_port = ntohs(udp_hdr->uh_dport);

		// Compute packet payload size.
		nextPacket.payload_size = (ntohs(udp_hdr->uh_ulen) - UDP_HDR_SIZE);
	}
	else
		return -1;

	return 0;
}

int CaptureEngine::getNextPacketStr(std::string& nextPacketStr)
{
	IPV4_PACKET nextPacket;

	if (getNextPacket(nextPacket) == -1)
		return -1;

	// Use sstream to build packet string.
	std::stringstream packSStream;

	// Add protocol.
	if (nextPacket.protocol == TCP)
		packSStream << "TCP:";
	else
		packSStream << "UDP:";

	// Add addresses, ports, and payload stats.
	packSStream << IPV4AddrToStr(nextPacket.source_address) << ":"
		        << nextPacket.source_port << ":"
		        << IPV4AddrToStr(nextPacket.destination_address) << ":"
		        << nextPacket.destination_port << ":"
				<< nextPacket.payload_size;

	// Finaly, copy data to string.
	nextPacketStr = packSStream.str();

	return 0;
}

void CaptureEngine::stopCapture()
{
	// Free compiled filter code if used.
	if (filterSet)
	{
		pcap_freecode(&engineFilter);
		filterSet = false;
	}

	// Cleanup after capture session if started.
	if (engineHandle)
	{
		pcap_close(engineHandle);
		engineHandle = nullptr;
	}
}

int CaptureEngine::getDeviceCount()
{
	return static_cast<int>(deviceNames.size());
}

std::string CaptureEngine::getDeviceName(const int deviceIndex)
{
	return deviceNames[deviceIndex];
}

std::string CaptureEngine::getDeviceDescription(const int deviceIndex)
{
	return deviceDescriptions[deviceIndex];
}

std::string CaptureEngine::getLibVersion()
{
	return pcap_lib_version();
}

std::string CaptureEngine::getEngineError()
{
	return engineError;
}

int Shim::strToCSTR(const std::string& str, char* cstr, size_t size)
{
	// Refuse to access invalid memory.
	if (size != (str.length() + 1))
	{
		return -1;
	}

	int i = 0;

	// Set cstring char by char.
	for (char c : str)
	{
		cstr[i] = c;
		i++;
	}

	// Cstrings must be null terminated.
	cstr[i] = '\0';

	// All good signal.
	return 0;
}
