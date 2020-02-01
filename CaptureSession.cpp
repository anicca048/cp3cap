
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <utility>
#include <cstdint>          //uint8_t
#include <cstdlib>          //NULL

extern "C"
{
    #include <arpa/inet.h>      //ntohs(), ip4ToStr() (deprecated 'n ipv4 only)
    #include <pcap/pcap.h>
    #include <netinet/in.h>
}

#include "CaptureSession.h"
#include "Packets.h"

using std::swap;
using std::string;
using std::vector;
using std::to_string;
using std::unique_lock;

using CaptureSession::Capture_Session;
using CaptureSession::Network_Connection;

using Packets::ipVer;
using Packets::ipHLen;
using Packets::isLocal;
using Packets::tcpHlen;
using Packets::ip4ToStr;
using Packets::IP_Header;
using Packets::TCP_Header;
using Packets::UDP_Header;
using Packets::Ethernet_Header;

bool Network_Connection::operator==(Network_Connection conn)
{
    //if IPs and ports (or inverse) are the same then it is the same connection
    if ((this->srcIP == conn.srcIP && this->srcPort == conn.srcPort)
                                         &&
            (this->dstIP == conn.dstIP && this->dstPort == conn.dstPort))
    {
        return true;
    }
    else if ((this->srcIP == conn.dstIP && this->srcPort == conn.dstPort)
                                            &&
             (this->dstIP == conn.srcIP && this->dstPort == conn.srcPort))
    {
        return true;
    }
    else
    {
        return false;
    }
}

int CaptureSession::stringToCSTR(const string &cppstr, char *cstr,
                                 const unsigned int cstrLength)
{
    //Refuse to access invalid memory
    if (cstrLength != (cppstr.length() + 1))
    {
        return -1;
    }

    int i = 0;

    //Set cstring char by char
    for (char c : cppstr)
    {
        cstr[i] = c;
        i++;
    }

    //Cstrings must be null terminated
    cstr[i] = '\0';

    //All good signal
    return 0;
}

int CaptureSession::setupCaptureSession(Capture_Session &currentSession)
{
    //Capture Interface init and checking

    //Lock all currentSession resources for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);
  
    //Pcap error message buffer with WinPcap overflow protection
    char pcapErrorBuffer[PCAP_ERRBUF_SIZE * 4];

    //Convert C++ string to cstr and create pcap device name
    int deviceStrSize = (currentSession.captureDevice.length() + 1);
    char pcapDevice[deviceStrSize];

    //Make sure string conversion didn't fail
    if (stringToCSTR(currentSession.captureDevice, pcapDevice, deviceStrSize) == -1)
    {
        currentSession.pcapSessionError = "string conversion failed.";
        return -1;
    }

    char *pPcapDevice = pcapDevice;

    //generate libpcap interface list
    pcap_if_t *deviceList;      //Pcap interface struct for device list
    pcap_if_t *device;          //Pcap device list proxy for loop code clarity
    bpf_u_int32 deviceNetwork;  //Pcap device network address for filter
    bpf_u_int32 deviceNetmask;  //Pcap device netmask for filter

    //Grab pcap device list and check for retrieval error
    if (pcap_findalldevs(&deviceList, pcapErrorBuffer) == -1)
    {
        currentSession.pcapSessionError = pcapErrorBuffer;
        return -1;
    }

    //Create device list vector from pcap interface struct
    for (device = deviceList; device != nullptr; device = device->next)
    {
        currentSession.captureDeviceList.push_back(device->name);
    }

    //Cleanup memory from pcap interface lookup
    pcap_freealldevs(deviceList);

    //CHECK DEVICE
    bool deviceCheck = false;

    for (string devName : currentSession.captureDeviceList)
    {
        if (currentSession.captureDevice == devName)
        {
            //Device name found
            deviceCheck = true;
            break;
        }
    }

    if (deviceCheck == false)
    {
        currentSession.pcapSessionError = "invalid device name";
        return -1;
    }

    //Get network and netmask address for filter compilation and check for error
    if (pcap_lookupnet(pPcapDevice, &deviceNetwork, &deviceNetmask,
                       pcapErrorBuffer) == -1)
    {
        //Not a critical error, just set these values incase of error
        deviceNetwork = 0;
        deviceNetmask = PCAP_NETMASK_UNKNOWN;
    }

    //Libpcap init and checking

    //Get library version for user interface
    currentSession.pcapLibVersion = pcap_lib_version();

    //Pcap loop settings
    int packetCaptureLength = 1518;     //Packet byte capture limit
    int readTimeOutMS = 755;            //Packet read timeout
    int promiscMode = 1;                //Promiscuous mode toggle

    //Create capture session handle
    currentSession.pcapSessionHandle = pcap_open_live(pPcapDevice, packetCaptureLength,
                                                      promiscMode, readTimeOutMS,
                                                      pcapErrorBuffer);

    //Ensure no errors occured opening session handle
    if (!currentSession.pcapSessionHandle)
    {
        currentSession.pcapSessionError = pcapErrorBuffer;
        return -1;
    }

    //Device must have a supported data link layer type
    currentSession.deviceDataLink = pcap_datalink(currentSession.pcapSessionHandle);

    switch (currentSession.deviceDataLink)
    {
        //Ethernet
        case DLT_EN10MB:
        {
            break;
        }
        //RAW IP
        case DLT_RAW:
        {
            break;
        }
        //Unsupported
        default:
        {
            currentSession.pcapSessionError = "unsupported device datalink ID: " +
                                              to_string(currentSession.deviceDataLink);

            return -1;
        }
    }

    //Compile and set pcap capture filter if user chose to use one
    if (!currentSession.captureFilter.empty() && currentSession.captureFilter != "")
    {
        //Create Pcap filter
        int filterStrSize = (currentSession.captureFilter.length() + 1);
        char pcapFilter[filterStrSize];
        
        //Make sure string conversion didn't fail
        if (stringToCSTR(currentSession.captureFilter, pcapFilter, filterStrSize) == -1)
        {
            currentSession.pcapSessionError = "string conversion failed.";
            return -1;
        }

        //Compile pcap filter and check for error
        if (pcap_compile(currentSession.pcapSessionHandle, &currentSession.compiledFilter,
                         pcapFilter, deviceNetmask, deviceNetwork) == -1)
        {
            currentSession.pcapSessionError = pcap_geterr(currentSession.pcapSessionHandle);
            return -1;
        }

        //Bind pcap filter to session handle and check for error
        if (pcap_setfilter(currentSession.pcapSessionHandle, &currentSession.compiledFilter) == -1)
        {
            currentSession.pcapSessionError = pcap_geterr(currentSession.pcapSessionHandle);
            return -1;
        }
    }

    return 0;
}

int CaptureSession::startCaptureSession(Capture_Session &currentSession)
{
    //Lock all currentSession resources for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    //SUPER DANGEROUS METHOD TO PASS NEEDED INFO WITHOUT GLOBALS
    uint8_t *pCurrentSession = reinterpret_cast<uint8_t *>(& currentSession);
    //SUPER DANGEROUS METHOD TO PASS NEEDED INFO WITHOUT GLOBALS


    int captureCount = -1;  //Packet capture limit, -1 for infinite

    //Free currentSession resources before we enter loop
    sessionLock.unlock();

    //Start infinite libpcap packet capture loop
    /*while (true)
    {
        int pcapLoopStatus = pcap_loop(currentSession.pcapSessionHandle, captureCount,
                                       pcapLoopCallback, pCurrentSession);

        //Check for loop error (-1 for error, -2 for interupt)
        if (pcapLoopStatus == -1)
        {
            currentSession.pcapSessionError = pcap_geterr(currentSession.pcapSessionHandle);
            break;
        }
        else if (pcapLoopStatus == -2)
        {
            break;
        }
    }*/

    int pcapLoopStatus = pcap_loop(currentSession.pcapSessionHandle, captureCount,
                                       pcapLoopCallback, pCurrentSession);

    //Check for loop error (-1 for error, -2 for interupt)
    if (pcapLoopStatus == -1)
    {
        currentSession.pcapSessionError = pcap_geterr(currentSession.pcapSessionHandle);
    }

    //Libpcap session cleanup

    //Relock currentSession resources for thread
    sessionLock.lock();

    //Check if using a pcap filter
    if (!currentSession.captureFilter.empty() && currentSession.captureFilter != "")
    {
        //Filter memory cleanup
        pcap_freecode(&currentSession.compiledFilter);
    }

    //Check if capture session initialization has occured
    if (currentSession.pcapSessionHandle)
    {
        //Close capture session
        pcap_close(currentSession.pcapSessionHandle);
    }
    
    if(!currentSession.pcapSessionError.empty() && currentSession.pcapSessionError != "")
    {
        return -1;
    }
    
    return 0;
}

void CaptureSession::stopCaptureSession(Capture_Session &currentSession)
{
    //Lock pcapSessionHandle resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    if (currentSession.pcapSessionHandle)
    {
        pcap_breakloop(currentSession.pcapSessionHandle);
    }
}

void CaptureSession::pcapLoopCallback(uint8_t *pCallbackArgs, const struct pcap_pkthdr *pktHeader,
                                      const uint8_t *packet)
{
    //SUPER DANGEROUS METHOD TO PASS ARGUMENTS WITHOUT GLOBALS
    Capture_Session *pCurrentSession = reinterpret_cast<Capture_Session *>(pCallbackArgs);
    Capture_Session &currentSession = * pCurrentSession;

    //Protocol analysis

    unsigned int ipHdrOff = 0;     //Offset for internet protocol after DL strip

    const struct IP_Header *ip_hdr = nullptr;                //IP header ptr
    const struct TCP_Header *tcp_hdr = nullptr;              //TCP header ptr
    const struct UDP_Header *udp_hdr = nullptr;              //UDP header ptr

    uint8_t  ip_ver;            //IP version (4 or 6)
    uint16_t ip_hdr_size;       //IP header size
    uint16_t tcp_hdr_size;      //TCP header size

    //Determine offset for IP header based on datalink type
    switch (pCurrentSession->deviceDataLink)
    {
        //Ethernet
        case DLT_EN10MB:
        {
            const struct Ethernet_Header *ethernet_hdr = nullptr;    //Ethernet header ptr

            //Check for damaged ethernet packet
            if (pktHeader->caplen < ETHERNET_HDR_SIZE)
            {
                return;
            }

            //Define ethernet header
            ethernet_hdr = reinterpret_cast<const struct Ethernet_Header *>(packet);

            //Drop non IPv4 packets
            if (ntohs(ethernet_hdr->ether_type) != ETHERNET_TYPE_IPV4)
            {
                return;
            }

            //Check for damaged IPV4 packet
            if (pktHeader->caplen < (ETHERNET_HDR_SIZE + IPV4_HEADER_MIN_LEN))
            {
                return;
            }

            //Use ethernet header for ipheader offset
            ipHdrOff = ETHERNET_HDR_SIZE;

            break;
        }
        //RAW IP
        case DLT_RAW:
        {
            //Check for damaged IPV4 packet
            if (pktHeader->caplen < IPV4_HEADER_MIN_LEN)
            {
                return;
            }

            //raw ip has no offset for ip heaser
            ipHdrOff = 0;

            break;
        }
    }

    ip_hdr = reinterpret_cast<const struct IP_Header *>(packet + ipHdrOff);

    ip_hdr_size = ipHLen(ip_hdr);
    ip_ver = ipVer(ip_hdr);

    //Drop non IPv4 (IPv6) packets.
    if (ip_ver != IP_TYPE_V4)
    {
        return;
    }

    //Drop packets with invalid IP Header size
    if (ip_hdr_size < IPV4_HEADER_MIN_LEN)
    {
        return;
    }

    //Create connection object for processing packet
    Network_Connection newConn;
    newConn.packetCount = 1;
    newConn.srcIP = ip4ToStr(ip_hdr->ip_src);
    newConn.dstIP = ip4ToStr(ip_hdr->ip_dst);

    //Drop packets of unsupported protocols, or compare to connections list
    if (ip_hdr->ip_p == IPPROTO_TCP)
    {
        //Check for damaged tcp packet
        if (pktHeader->caplen < (ipHdrOff + IPV4_HEADER_MIN_LEN + TCP_HEADER_MIN_LEN))
        {
            return;
        }

        // define tcp header by offset
        tcp_hdr = reinterpret_cast<const struct TCP_Header *>
                                  (packet + ipHdrOff + ip_hdr_size);
        tcp_hdr_size = tcpHlen(tcp_hdr);

        //Drop packets with invalid tcp header size
        if (tcp_hdr_size < TCP_HEADER_MIN_LEN)
        {
            return;
        }

        //Set connection protocol
        newConn.protocol = "TCP";

        //Set connection ports
        newConn.srcPort = ntohs(tcp_hdr->th_sport);
        newConn.dstPort = ntohs(tcp_hdr->th_dport);

        //Compute tcp payload wihtout using tcp segment section / option feild
        newConn.dataSent = (ntohs(ip_hdr->ip_len) - (ip_hdr_size + tcp_hdr_size));
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP)
    {
        //check for damaged udp packet
        if (pktHeader->caplen < (ipHdrOff + IPV4_HEADER_MIN_LEN + UDP_HDR_SIZE))
        {
            return;
        }

        //Define udp header by offset
        udp_hdr = reinterpret_cast<const struct UDP_Header *>
                                  (packet + ipHdrOff + ip_hdr_size);

        //Set connection protocol
        newConn.protocol = "UDP";

        //Set connection ports
        newConn.srcPort = ntohs(udp_hdr->uh_sport);
        newConn.dstPort = ntohs(udp_hdr->uh_dport);

        //Compute packet payload size
        newConn.dataSent = (ntohs(udp_hdr->uh_ulen) - UDP_HDR_SIZE);
    }
    else
    {
        return;
    }

    //Lock connectionlist resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    //If connection is pre-existing then update details and quit
    for (Network_Connection &connection : currentSession.connectionsList)
    {
        //Skip connections of different protocols
        if (connection.protocol != newConn.protocol)
        {
            continue;
        }

        //Check for connection by packet direction and inverse
        if (connection == newConn)
        {
            //Update connection stats
            connection.dataSent += newConn.dataSent;
            connection.packetCount++;
            return;
        }
    }

    //Connection was not pre-existing so we need to add it to the connections list

    //Ensure that local / private ip's are set as srcIP
    if (Packets::isLocal(ip_hdr->ip_dst) && !Packets::isLocal(ip_hdr->ip_src))
    {
        //Swap IP addresses
        swap(newConn.srcIP, newConn.dstIP);
        //Swap ports
        swap(newConn.srcPort, newConn.dstPort);
    }

    //Update connection list with new connection
    currentSession.connectionsList.push_back(newConn);

    //End callback loop
}
