
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "CaptureEngine.h"
#include "CaptureSession.h"

using std::mutex;
using std::string;
using std::thread;
using std::vector;
using std::unique_lock;

using CaptureEngine::CEngine;

using CaptureSession::Network_Connection;
using CaptureSession::stopCaptureSession;
using CaptureSession::setupCaptureSession;
using CaptureSession::startCaptureSession;

int CEngine::setupEngine()
{
    //Pcap session init (most errors caught here)
    if (setupCaptureSession(currentSession) == -1)
    {
        return -1;
    }

    return 0;
}

int CEngine::startEngine()
{
    //Start pcap loop
    if (startCaptureSession(currentSession) == -1)
    {
        return -1;
    }

    return 0;
}

void CEngine::stopEngine()
{
    //Break pcap loop (on SIGINT or SIGTERM)
    stopCaptureSession(currentSession);
}

string CEngine::getError()
{
    //Lock captureDevice resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    return currentSession.pcapSessionError;
}

string CEngine::getCaptureDevice()
{
    //Lock captureDevice resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    return currentSession.captureDevice;
}

string CEngine::getCaptureFilter()
{
    //Lock captureFilter resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    return currentSession.captureFilter;
}

string CEngine::getPcapVersion()
{
    //Lock pcapLibVersion resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    return currentSession.pcapLibVersion;
}

vector<string> CEngine::getDeviceList()
{
    //Lock captureDeviceList resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    return currentSession.captureDeviceList;
}

vector<Network_Connection> CEngine::getConnectionsList()
{
    //Lock connectionsList resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    return currentSession.connectionsList;
}

void CEngine::clearConnectionsList()
{
    //Lock connectionsList resource for thread
    unique_lock<mutex> sessionLock(currentSession.sessionMutex);

    //Clear connectionsListVector to remove stale entries
    currentSession.connectionsList.clear();
}
