
#ifndef PACKETS_H   //Include Gaurd
#define PACKETS_H

#include <string>
#include <cstdint>          //uint8_t, uint16_t

extern "C"
{
    #include <arpa/inet.h>
    #include <netinet/in.h>     //in_addr
}

#define ETHERNET_HDR_SIZE 14      //Ethernet headers are always 14 bytes
#define ETHERNET_ADDR_LEN 6       //Ethernet mac addresses are always 6 bytes
#define ETHERNET_TYPE_IPV4 0x0800 //IPv4 code in ethernet type section (0x0800)

#define IP_TYPE_V4 4              //IPv4 version number for header check
#define IPV4_HEADER_MIN_LEN 20    //Minimum byte size of ipv4 header
#define IPV4_CLASS_A_MIN  0x0A000000    //Class A range 10.0.0.0/8
#define IPV4_CLASS_A_MASK 0xFF000000    //Class A netmask 255.0.0.0
#define IPV4_CLASS_B_MIN  0xAC100000    //Class B min range 172.16.0.0/12
#define IPV4_CLASS_B_MAX  0xAC1F0000    //Class B max range 172.31.0.0/12
#define IPV4_CLASS_B_MASK 0xFFF00000    //Class B netmask 255.240.0.0
#define IPV4_CLASS_C_MIN  0xC0A80000    //Class C range 192.168.0.0/16
#define IPV4_CLASS_C_MASK 0xFFFF0000    //Class C netmask 255.255.0.0
#define IPV4_LOCAL_MIN    0x7F000000    //Local range 127.0.0.0/8
#define IPV4_LOCAL_MASK   0xFF000000    //Local netmask 255.0.0.0

#define TCP_HEADER_MIN_LEN 20
#define UDP_HDR_SIZE 8            //UDP header is always 8 bytes

using std::string;

namespace Packets
{
    //Ethernet header object for packet processing
    struct Ethernet_Header
    {
        uint8_t  ether_dhost[ETHERNET_ADDR_LEN];    //Destination mac address
        uint8_t  ether_shost[ETHERNET_ADDR_LEN];    //Source mac address
        uint16_t ether_type;                        //Protocol (IP, arp)
    };

    //Ethernet header object for packet processing
    struct IP_Header
    {
        uint8_t  ip_vhl;        //IP version and header length
        uint8_t  ip_tos;        //IP packet type of service
        uint16_t ip_len;        //IP packet length
        uint16_t ip_id;         //IP packet identification
        uint16_t ip_off;        //IP fragment offset field
        uint8_t  ip_ttl;        //IP packet time to live
        uint8_t  ip_p;          //packet transmission layer protocol
        uint16_t ip_sum;        //IP packet checksum
        struct in_addr ip_src;  //IP source address
        struct in_addr ip_dst;  //IP destination address
    };

    //TCP header object for packet processing
    struct TCP_Header
    {
        uint16_t th_sport;  //TCP source port
        uint16_t th_dport;  //TCP destination port
        uint32_t th_seq;    //TCP stream packet sequence number
        uint32_t th_ack;    //TCP stream packet acknowledgement number
        uint8_t  th_offx2;  //TCP packet data offset and reserved section
        uint8_t  th_flags;  //TCP stream packet flags
        uint16_t th_win;    //TCP stream packet window
        uint16_t th_sum;    //TCP packet checksum
        uint16_t th_urp;    //TCP stream packet urgent pointer
    };

    //UDP header object for packet processing
    struct UDP_Header
    {
        uint16_t uh_sport;  //UDP source port
        uint16_t uh_dport;  //UDP destination port
        uint16_t uh_ulen;   //UDP packet length
        uint16_t uh_sum;    //UDP packet checksum
    };

    //Check if ip is in private class range
    inline bool isLocal(const struct in_addr &ipAddr)
    {
        //Binary compare for netork range
        if ((ntohl(ipAddr.s_addr) & IPV4_CLASS_A_MASK) == IPV4_CLASS_A_MIN)
        {
            return true;
        }
        else if (((ntohl(ipAddr.s_addr) & IPV4_CLASS_B_MASK) >= IPV4_CLASS_B_MIN)
                 &&
                 ((ntohl(ipAddr.s_addr) & IPV4_CLASS_B_MASK) <= IPV4_CLASS_B_MAX))
        {
            return true;
        }
        else if ((ntohl(ipAddr.s_addr) & IPV4_CLASS_C_MASK) == IPV4_CLASS_C_MIN)
        {
            return true;
        }
        else if ((ntohl(ipAddr.s_addr) & IPV4_LOCAL_MASK) == IPV4_LOCAL_MIN)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    //IP version calculator
    inline uint8_t ipVer(const struct IP_Header *&ipHdr)
    {
        return ((ipHdr->ip_vhl & 0xf0) >> 4);    //First nibble has version    
    }
    
    //IP header length calculator
    inline uint16_t ipHLen(const struct IP_Header *&ipHdr)
    {
        return ((ipHdr->ip_vhl & 0x0f) * 4);    //Second nibble has length
    }

    //TCP header length calculator
    inline uint16_t tcpHlen(const struct TCP_Header *&tcpHdr)
    {
        return (((tcpHdr->th_offx2 & 0xf0) >> 4) * 4); //nibble 1 has len
    }

    inline struct in_addr strToIP4(string IP)
    {
        struct in_addr ipStruct;
        inet_pton(AF_INET, IP.c_str(), &ipStruct);
        return ipStruct;
    }

    inline string ip4ToStr(struct in_addr IP)
    {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &IP, ipStr, INET_ADDRSTRLEN);
        return ipStr;
    }
}

#endif
