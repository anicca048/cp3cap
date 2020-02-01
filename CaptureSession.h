
#ifndef CAPTURESESSION_H
#define CAPTURESESSION_H

#include <mutex>
#include <string>
#include <vector>
#include <cstdint>          //uint8_t
#include <cstdlib>          //NULL

extern "C"
{
    #include <pcap/pcap.h>
}

using std::mutex;
using std::string;
using std::vector;

namespace CaptureSession
{
    //Connection object built from packets.
    class Network_Connection
    {
        public:
            string srcIP;                //Connection local ip address
            string dstIP;                  //Connection remote ip address
            string protocol;                //Connection protocol (tcp, udp)
            uint16_t srcPort;            //Connection protocol source port
            uint16_t dstPort;              //Connection protocol destination port
            unsigned long long packetCount; //all packets sent
            unsigned long long dataSent;    //total of all data in payloads sent

            //Overload operator for connection comparison in pcap callback loop
            bool operator==(Network_Connection conn);
    };
    
    //Session object containing capture session info requiring complex scope
    //Anything that will need to be passed to different threads goes here
    //Must be pcap callback compatable (IE: a struct(sequential bundle of values))
    struct Capture_Session
    {
        //mutex for creating session resource locks
        mutex sessionMutex;

        //Critical to pcap session init and ui
        int deviceDataLink;                         //Datalink header type
        string captureDevice;                       //Pcap interface name
        string captureFilter;                       //Pcap interface string
        string pcapLibVersion;                      //Place to store libpcap ver
        string pcapSessionError;                    //Place to store error hints
        vector<string> captureDeviceList;           //List of Pcap interfaces

        //Critical to main packet loop and ui
        pcap_t *pcapSessionHandle;                  //Pcap session handle pointer
        struct bpf_program compiledFilter;          //Compiled pcap filter
        vector<Network_Connection> connectionsList; //List of captured connections
    };
    
    //Conversion to convert c++ string object to a mutable c_str for pcap functions
    //Potentially dangerous so retuns -1 if outofbounds access is likely
    int stringToCSTR(const string &cppstr, char *cstr, const unsigned int cstrLength);

    int setupCaptureSession(Capture_Session &currentSession);
    
    //Creates and initilizes libpcap capture session and starts pcap_loop()
    int startCaptureSession(Capture_Session &currentSession);

    //Calls pcap_breakloop() to stop pcap_loop()
    void stopCaptureSession(Capture_Session &currentSession);
    
    //Callback function for pcap_loop(), creates list of connection from packets
    void pcapLoopCallback(uint8_t *pCallbackArgs, const struct pcap_pkthdr *pktHeader,
                          const uint8_t *packet);
    
    //Possibly overboard safegaurd due to pointer reinterpretation
    static_assert((sizeof(uint8_t *) == sizeof(Capture_Session *)),
                  "Pointer sizes are incompatable!\n");
}

#endif
