
/*
 * Copyright (c) 2018 anicca048
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <mutex>
#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <string>
#include <vector>
#include <iomanip>
#include <csignal>
#include <cstdlib>
#include <sstream>
#include <iostream>
#include <algorithm>

#ifdef _MSC_VER

#error Windows platform not yet fully supported (becuase of ncurses and getopt).

#else

#include <unistd.h> 
#include <ncurses.h>

#endif

#include "Shim.h"
#include "Connections.h"

#define PROGRAM_VERSION_STR "CP3cap v1.0.2"

#define PACKET_BATCH_COUNT 500
#define CONN_LIST_HEADER "#   Type    LocalAddress:Port  RT   RemoteAddress:Port  PacketCount DataSent   "

using Shim::CaptureEngine;
using Connections::Connection;
using Connections::NO_MATCH;
using Connections::REVERSE_MATCH;

// Handle user or system supplied interrupts and terminations.
void signalHandler(int);
// Prints help screen.
void printHelp();
// Used to sort connection list by multiple directives.
bool connSwapTest(const Connection&, const Connection&);
// Sniffs packets with capture engine and adds them to queue.
void packetCapture();

// Global flag for stoping main ui loop and capture thread from signal handler.
std::atomic_bool stopUILoop = false;

// Global pointer to capture engine for use by both threads.
std::unique_ptr<CaptureEngine> cengPtr;
// Global pointer to queue for handling packets between threads.
std::unique_ptr<std::queue<IPV4_PACKET>> queuePtr;
// Global mutex for locking queue between threads.
std::mutex queueMtx;

int main(int argc, char *argv[])
{
    // Handle process.
    signal(SIGINT, signalHandler);  // Handle ^C events.
    signal(SIGQUIT, signalHandler); // Handle ^\ events.
    signal(SIGTERM, signalHandler); // Handle termination incase of loop hang.

    // Procces command line arguments.
    std::string arg_interface = "";
    std::string arg_filter = "";

    int c = 0;

    while((c = getopt(argc, argv, "vhpi:f:")) != -1 )
    {
        switch(c)
        {
            case 'i':
            {
                if(optarg)
                {
                    arg_interface = optarg;
                }
                else
                {
                    std::cerr << "[!] Error: Invalid Usage!" << std::endl;
                    printHelp();

                    return 1;
                }

                break;
            }
            case 'f':
            {
                if(optarg)
                {
                    arg_filter = optarg;
                }
                else
                {
                    std::cerr << "[!] Error: Invalid Usage!" << std::endl;
                    printHelp();

                    return 1;
                }

                break;
            }
            case 'p':
            {
                // Create a capture engine to print device list.
                cengPtr.reset(new CaptureEngine);

                if (cengPtr->genDeviceList() == -1)
                {
                    std::cout << "[!] Error retrieving device list: "
                              << cengPtr->getEngineError() << std::endl;

                    return 1;
                }

                // Get device count for loop.
                int deviceCount = cengPtr->getDeviceCount();

                std::cout << std::endl
                          << "[#] Pcap Devices:" << std::endl
                          << "[^]" << std::endl;
    
                // Print list of available pcap devices.
                for (int i = 0; i < deviceCount; i++ )
                {
                    std::cout << "[*] " << cengPtr->getDeviceName(i)
                              << std::endl;
                }

                std::cout << "[^]" << std::endl;
                return 0;
            }
            case 'v':
            {
                std::cout << std::endl
                          << PROGRAM_VERSION_STR << std::endl;

                return 0;
            }
            case 'h':
            {
                std::cout << std::endl;

                printHelp();

                return 0;
            }
            default:
            {
                std::cerr << "[!] Error: Invalid Usage!" << std::endl;
                printHelp();

                return 1;
            }
        }
    }

    // Check for device and filter arguments.
    if (arg_interface == "" || arg_interface.empty())
    {
        std::cerr << "[!] Error: Invalid Usage!" << std::endl;
        printHelp();

        return 1;
    }

    // Create capture engine.
    cengPtr.reset(new CaptureEngine);

    // Generate device list.
    if (cengPtr->genDeviceList() == -1)
    {
        std::cout << "[!] Error retrieving device list: "
                  << cengPtr->getEngineError() << std::endl;

        return 1;
    }

    // Initilize packet capture.
    if (cengPtr->startCapture(arg_interface, arg_filter) == -1)
    {
        std::cout << "[!] Error initilizing capture engine: "
                  << cengPtr->getEngineError() << std::endl;

        return 1;
    }

    std::cout << std::endl
              << "[+] CP3cap starting." << std::endl;
    
    std::cout << "[#] " << cengPtr->getLibVersion() << std::endl
              << "[#] Device: " << arg_interface << std::endl;

    if ((!arg_filter.empty()) && (arg_filter != ""))
        std::cout << "[#] Filter: " << arg_filter << std::endl;

    //
    // Main UI and capture loop.
    //

    // Initilize queue and set pointer.
    queuePtr.reset(new std::queue<IPV4_PACKET>);

    // Create connection list vector.
    std::vector<Connection> cList;

    // Setup packet capture thread.
    std::thread packetThread(packetCapture);

    // Set UI paramaters.
    initscr();
    nodelay(stdscr, true);    // No delay for getch().
    cbreak();                 // No terminal line buffering.
    noecho();                 // No input echoing.
    nonl();                   // Better newline handling.
    intrflush(stdscr, false); // Don't flush screen on interupt.
    keypad(stdscr, true);     // Allow functional buttons.

    while (!stopUILoop)
    {
        // Create tracker for batch processing.
        int packetsProcessed = 0;

        for (; packetsProcessed < PACKET_BATCH_COUNT; packetsProcessed++)
        {
            // Create packet object.
            IPV4_PACKET newPacket;

            // Get lock on queue.
            std::unique_lock<std::mutex> queueLock(queueMtx);

            // Grab packet if queue is not empty.
            if (!queuePtr->empty())
            {
                newPacket = queuePtr->front();
                queuePtr->pop();
            }
            // If queue is empty, break batch loop.
            else
                break;

            // Manually release lock on queue if loop is going to continue.
            queueLock.unlock();

            // Create new connection from packet.
            Connection newConn(newPacket);

            // Connection matching flag.
            bool connFound = false;

            // Check if connection already exists and if so update stats.
            for (Connection& conn : cList)
            {
                if (conn.MatchConnection(newConn) != NO_MATCH)
                {
                    connFound = true;

                    if ((conn.state != "<>") && (newConn.state != conn.state))
                        conn.state = "<>";
                    else if (conn.MatchConnection(newConn) == REVERSE_MATCH)
                        conn.state = "<>";

                    conn.packetCount++;
                    conn.dataSent += newConn.dataSent;

                    break;
                }
            }

            // Add conn to list becuase it doesn't already exist.
            if (!connFound)
                cList.push_back(newConn);
        }

        // Sort connection list if new packets were processed.
        if (packetsProcessed != 0)
            std::sort(cList.begin(), cList.end(), connSwapTest);

        // clear old window.
        clear();

        printw("%s\n", CONN_LIST_HEADER);

        // Create screenbounds safegaurd to prevent pourover.
        int maxScrX, maxScrY = 0;
        bool boundsIssue = false;
        getmaxyx(stdscr, maxScrY, maxScrX);

        // Figure out if we need.
        if ((!cList.empty()) && (maxScrY > 0)
            && ((static_cast<int>(cList.size()) + 1) > maxScrY))
            boundsIssue = true;

        // Connection number iterator.
        int iter = 0;

        // Print connection list.
        for (Connection &conn : cList)
        {
            // Create sstream for setting a line of ncurses screen.
            std::stringstream lineStream;

            iter++;

            // Check if reached screen boundry and stop if so.
            if (boundsIssue == true && (iter + 1) == maxScrY)
            {
                printw("### Connections Beyond Screen Bounds ###\n");
                break;
            }

            // Print a connection.
            lineStream << std::left << std::setw(3) << iter << " "
                       << std::setw(4) << conn.protocol << " " << std::right
                       << std::setw(15) << conn.srcIP << ":" << std::left
                       << std::setw(5) << conn.srcPort << " "
                       << std::setw(2) << conn.state << " " << std::right
                       << std::setw(15) << conn.dstIP << ":" << std::left
                       << std::setw(5) << conn.dstPort << " "
                       << std::setw(11) << conn.packetCount << " "
                       << conn.dataSent;

            // Convert sstream to c_str and print with ncurses.
            printw("%s\n", lineStream.str().c_str());
        }

        // Write updated window to screen.
        refresh();

        // User control check.
        char uInput = '\0';
        uInput = getch();
        
        // Process user control.
        switch (uInput)
        {
            // Pause printing of connection list.
            case 'p':
            {
                printw("\nOutput Paused");
                refresh();
                 
                uInput = '\0';
            
                while ((uInput != 'p') && (!stopUILoop))
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(111));
                    uInput = getch();
                }

                break;
            }
            // Clear list of connections.
            case 'c':
            {
                // Get lock on queue.
                std::unique_lock<std::mutex> queueLock(queueMtx);

                // Clear queue.
                queuePtr.reset(new std::queue<IPV4_PACKET>);
                // Clear conn list.
                cList.clear();

                refresh();

                break;
            }
            // Quit the loop.
            case 'q':
                stopUILoop = true;
                break;
        }
        
        // pre sleep kill switch check.
        if (stopUILoop)
            break;

        // Sleep between screen writes.
        std::this_thread::sleep_for(std::chrono::milliseconds(333));
    }

    // Wait for thread to exit.
    packetThread.join();

    // UI cleanup.
    clear();
    refresh();
    endwin();

    // Engine cleanup.
    cengPtr->stopCapture();
    cengPtr.reset();

    // Queue cleanup.
    queuePtr.reset();

    std::cout << "[+] Exiting." << std::endl;
    return 0;
}

void packetCapture()
{
    while (!stopUILoop)
    {
        // Create new packet object for adding to queue.
        IPV4_PACKET newPacket;

        // Fill in packet information, or go to next loop iteration on fail.
        if (cengPtr->getNextPacket(newPacket) == -1)
            continue;

        // Create lock on queue.
        std::unique_lock<std::mutex> queueLock(queueMtx);

        // Add packet to queue.
        queuePtr->push(newPacket);
    }
}

void printHelp()
{
    std::cout << "[#] [ -i <interface>   (libpcap interface)        ]" << std::endl
              << "[#] [ -f <pcap_filter> (libpcap capture filter)   ]" << std::endl
              << "[#] [ -p               (list libpcap interfaces)  ]" << std::endl
              << "[#] [ -v               (Show program version info)]" << std::endl
              << "[#] [ -h               (show help message)        ]" << std::endl;
}

void signalHandler(int sigNum)
{
    // Handle user interrupt.
    if (sigNum == SIGINT)
        stopUILoop = true;
    // Handle system supplied quit.
    else if (sigNum == SIGQUIT)
        stopUILoop = true;
    // Handle system supplied termination.
    else if (sigNum == SIGTERM)
        std::exit(EXIT_FAILURE);
}

bool connSwapTest(const Connection& connA, const Connection& connB)
{
    // Sort by most packets per connection.
    if (connA.packetCount > connB.packetCount)
        return true;
    // Sort secondarily by data sent.
    else if (connA.packetCount == connB.packetCount)
    {
        if (connA.dataSent > connB.dataSent)
            return true;
        // Sort by ip next.
		else if  (connA.dataSent == connB.dataSent)
        {
            if (connA.srcIP < connB.srcIP)
                return true;
            // Sort by port last.
            else if (connA.srcIP == connB.srcIP)
            {
                if (connA.srcPort < connB.srcPort)
                    return true;
            }
		}
    }
    
    return false;
}
