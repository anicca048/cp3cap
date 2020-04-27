
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

#include <unistd.h> 
#include <ncurses.h>

#include "Shim.h"
#include "Connections.h"

using Shim::CaptureEngine;
using Connections::Connection;
using Connections::NO_MATCH;
using Connections::REVERSE_MATCH;

// Handle user or system supplied interrupts and terminations.
void signalHandler(int);
// Prints help screen.
void printHelp();
// Used to print all available libpcap devices for capture.
void printDeviceList(CaptureEngine&);
// Used to sort connection list by multiple directives.
bool connSwapTest(const Connection&, const Connection&);

// Global flag for stoping main ui loop from signal handler.
bool stopUILoop = false;

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

    while((c = getopt(argc, argv, "hpi:f:")) != -1 )
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
                // Create a capture enging to print device list.
                CaptureEngine ceng;

                if (ceng.genDeviceList() == -1)
                {
                    std::cout << "[!] Error retrieving device list: "
                              << ceng.getEngineError() << std::endl;

                    return 1;
                }

                printDeviceList(ceng);
                return 0;
            }
            case 'h':
            {
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

    // Create capture engine for capturing packets.
    CaptureEngine ceng;

    // Generate device list.
    if (ceng.genDeviceList() == -1)
    {
        std::cout << "[!] Error retrieving device list: "
                  << ceng.getEngineError() << std::endl;

        return 1;
    }

    // Initilize packet capture.
    if (ceng.startCapture(arg_interface, arg_filter) == -1)
    {
        std::cout << "[!] Error initilizing capture engine: "
                  << ceng.getEngineError() << std::endl;

        return 1;
    }

    std::cout << "[+] CP3cap Loaded" << std::endl;
    
    std::cout << "[#] " << ceng.getLibVersion() << std::endl
              << "[#] Device: " << arg_interface << std::endl;

    if ((!arg_filter.empty()) && (arg_filter != ""))
        std::cout << "[#] Filter: " << arg_filter << std::endl;

    //
    // Main UI and capture loop.
    //

    // Create connection list vector.
    std::vector<Connection> cList;

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
        // Create packet object.
        IPV4_PACKET newPacket;

        // Fill in packet information, or go to next loop iteration on fail.
        if (ceng.getNextPacket(newPacket) == -1)
            continue;

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

        // Sort connection list.
        std::sort(cList.begin(), cList.end(), connSwapTest);

        // Use stringstream and string to use iomanip formating with printw().
        std::string line;
        std::stringstream lineStream;

        // clear old window.
        clear();

        // Print connection list column headers.
        lineStream << "#   Type    LocalAddress:Port  RT   RemoteAddress:Port  PacketCount DataSent   ";

        // Convert formated stream to a ncurses printable line of output.
        line = lineStream.str();
        lineStream.str("");
        printw("%s\n", line.c_str());

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
                       << std::setw(5) << conn.srcPort << " " << std::setw(2)
                       << conn.state << " " << std::right << std::setw(15)
                       << conn.dstIP << ":" << std::left << std::setw(5)
                       << conn.dstPort << " " << std::setw(11)
                       << conn.packetCount << " " << conn.dataSent;

            // Convert formated stream to a ncurses printable line of output.
            line = lineStream.str();
            lineStream.str("");
            printw("%s\n", line.c_str());
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
        //std::this_thread::sleep_for(milliseconds(111));
    }

    // UI cleanup.
    clear();
    refresh();
    endwin();

    // Engine cleanup.
    ceng.stopCapture();

    std::cout << "[+] Exiting." << std::endl;
    return 0;
}

void printHelp()
{
    std::cout << "[#] [ -i <interface>    (libpcap interface)       ]" << std::endl
              << "[#] [ -f <pcap_filter>  (libpcap capture filter)  ]" << std::endl
              << "[#] [ -p                (list libpcap interfaces) ]" << std::endl
              << "[#] [ -h                (show help message)       ]" << std::endl;
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

void printDeviceList(CaptureEngine& ceng)
{
    //(re)generate list of devices and get device count for loop.
    ceng.genDeviceList();
    int deviceCount = ceng.getDeviceCount();

    std::cout << "[#] Pcap Devices:\n"
              << "[^]\n";
    
    // Print list of available pcap devices.
    for (int i = 0; i < deviceCount; i++ )
    {
        std::cout << "[*] " << ceng.getDeviceName(i) << std::endl;
    }

    std::cout << "[^]\n";
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
