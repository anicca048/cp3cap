
#ifndef CAPTUREENGINE_H
#define CAPTUREENGINE_H

#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "CaptureSession.h"

using CaptureSession::Capture_Session;
using CaptureSession::Network_Connection;

namespace CaptureEngine
{
    //CaptureEngine object that handles the pcap init and packet handling
    class CEngine
    {
        public:
            //Constructor takes pcap interface and interface filter (empty by default)
            CEngine(string captureDevice, string captureFilter)
            {
                currentSession.captureDevice = captureDevice;
                currentSession.captureFilter = ("(udp or tcp) and (" + captureFilter + ")");
            }
            //Constructor takes just pcap interface
            CEngine(string captureDevice) : CEngine(captureDevice, "udp or tcp") {}

            //Pcap session init
            int setupEngine();
            //Start pcap loop
            int startEngine();
            //End pcap loop
            void stopEngine();

            //Session Accessors (cant be const because of mutex manipulation)
            string getError();
            string getPcapVersion();
            string getCaptureDevice();
            string getCaptureFilter();
            vector<string> getDeviceList();
            vector<Network_Connection> getConnectionsList();

            //Mutators
            void clearConnectionsList();

        private:
            //Capture session data
            Capture_Session currentSession;
    };
}

#endif
