
#pragma once

#ifndef _SHIM_H_
#define _SHIM_H_

#ifdef _MSC_VER

#include <WS2tcpip.h>
#include <WinSock2.h>

#else

#include <arpa/inet.h>
#include <netinet/in.h>

#endif

#include <string>
#include <cstdint>
#include <vector>

#include <pcap/pcap.h>

namespace Shim
{
	// Describes layer 4 protocol type.
	enum L4_PROTOCOL
	{
		UDP,
		TCP
	};

	// Holds relavent packet info for apps using Shim.
	struct IPV4_PACKET
	{
		in_addr source_address;
		in_addr destination_address;
		L4_PROTOCOL protocol;
		uint16_t source_port;
		uint16_t destination_port;
		uint32_t payload_size;
	};

	// Shim's core, interfaces with libpcap to make packet capture easier.
	class CaptureEngine
	{
		public:
			// Default ctor and dtor, manage dynamic memory used by class.
			CaptureEngine();
			~CaptureEngine();
			// Generates device name and description lists.
			int genDeviceList();
			// Does packet capture init.
			int startCapture(const int, std::string);
			int startCapture(std::string, std::string);
			// Gets the next packet from capture engine.
			int getNextPacket(IPV4_PACKET&);
			// Gets the next packet from capture engine as a shim packet string.
			int getNextPacketStr(std::string&);
			// Cleans up after packet capture init.
			void stopCapture();

			// Functions for accessing device names and descriptions.
		    int getDeviceCount();
			std::string getDeviceName(const int);
			std::string getDeviceDescription(const int);
			// Returns the libpcap / npcap library version string.
			std::string getLibVersion();
			// Gets the capture session error if there is one.
			std::string getEngineError();
		private:
			// Libpcap sesison handle.
			pcap_t* engineHandle = nullptr;
			// Libpcap bpf compiled capture filter.
			bpf_program* engineFilter = nullptr;
			bool filterSet = false;
			// DataLink type for device used during startCapture().
			int engineDataLink;

			// List of libpcap interface names.
			std::vector<std::string> deviceNames;
			// List of libpcap interface descriptions and addresses.
			std::vector<std::string> deviceDescriptions;
			// Holds error messages set during CEngine and libpcap operations.
			std::string engineError;
	};
}

#endif
