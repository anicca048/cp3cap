
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

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <iomanip>
#include <csignal>
#include <cstdlib>
#include <sstream>
#include <iostream>
#include <algorithm>

extern "C"
{
    #include <unistd.h>     //getopt()
    #include <ncurses.h>    //CLI GUI
}

#include "CaptureEngine.h"

using std::cin;
using std::cerr;
using std::cout;
using std::left;
using std::endl;
using std::setw;
using std::right;
using std::atomic;
using std::signal;
using std::string;
using std::thread;
using std::vector;
using std::unique_ptr;
using std::stringstream;
using std::chrono::milliseconds;

using CaptureEngine::CEngine;

//Global pointer to capture engine option for access by signalHandler()
unique_ptr<CEngine> pCaptureEngine;

//Global thread status var
atomic<bool> keepRunning;

//Prototypes
void uiLoop();
void signalHandler(int sigNum); //Pcap loop is infinite, so user might ^C
void printInterfaceList(vector<string> intList);
bool connSort(const Network_Connection connA, const Network_Connection connB);

int main(int argc, char *argv[])
{
    //Handle process
    signal(SIGINT, signalHandler);  //Handle ^C events
    signal(SIGQUIT, signalHandler); //Handle ^\ events
    signal(SIGTERM, signalHandler); //Handle termination incase of loop hang

    //Procces command line arguments
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
                    cerr << "[!] Error: Invalid Usage!" << endl;
                    cout << "[#] For help run: " << argv[0] << " -h\n";

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
                    cerr << "[!] Error: Invalid Usage!" << endl;
                    cout << "[#] For help run: " << argv[0] << " -h\n";

                    return 1;
                }

                break;
            }
            case 'p':
            {
                //Intilize fake engine and gen interface list
                pCaptureEngine = unique_ptr<CEngine>(new CEngine(""));
                pCaptureEngine->setupEngine();
                printInterfaceList(pCaptureEngine->getDeviceList());

                return 0;
            }
            case 'h':
            {
                cout << "[#] [ -i <interface>    (pcap capture interface)  ]" << endl
                     << "[#] [ -f <pcap_filter>  (pcap capture filter)     ]" << endl
                     << "[#] [ -p                (list capture interfaces) ]" << endl
                     << "[#] [ -h                (show help message)       ]" << endl;

                return 0;
            }
            default:
            {
                cerr << "[!] Error: Invalid Usage!" << endl;
                cout << "[#] For help run: " << argv[0] << " -h\n";

                return 1;
            }
        }
    }

    //Check for device and filter arguments
    if (arg_interface != "" && arg_filter != "")
    {
        pCaptureEngine = unique_ptr<CEngine>(new CEngine(arg_interface, arg_filter));
    }
    else if (arg_interface != "")
    {
        pCaptureEngine = unique_ptr<CEngine>(new CEngine(arg_interface));
    }
    else
    {
        cerr << "[!] Error: Invalid Usage!" << endl;
        cout << "[#] For help run: " << argv[0] << " -h\n";

        return 1;
    }

    int engineStatus = pCaptureEngine->setupEngine();

    if (engineStatus == -1)
    {
        string errorMessage = pCaptureEngine->getError();

        if (errorMessage == "invalid device name")
        {
            cerr << "[!] Error: Invalid Device: "
                 << pCaptureEngine->getCaptureDevice() << endl
                 << "[#] Use: " << argv[0] << " -p" << endl;
        }
        else
        {
            cout << "[!] Error: " << errorMessage << endl;
        }

        return 1;
    }

    //Start main capture and ui loops
    cout << "[+] CP3cap Loaded" << endl;
    
    //Give user session info
    cout << "[#] " << pCaptureEngine->getPcapVersion() << endl
         << "[#] Device: " << pCaptureEngine->getCaptureDevice() << endl;

    if (!pCaptureEngine->getCaptureFilter().empty() && pCaptureEngine->getCaptureFilter() != "")
    {
        cout << "[#] Filter: " << pCaptureEngine->getCaptureFilter() << endl;
    }

    //Start ui thread
    keepRunning = true;
    thread uiThread = thread(uiLoop);

    //Start pcap loop
    engineStatus = 0;
    engineStatus = pCaptureEngine->startEngine();

    //Do cleanup
    if (uiThread.joinable())
    {
        //Tell ui thread to stop
        keepRunning = false;

        //Wait for ui thread to stop
        uiThread.join();
    }

    //Check if there was a loop error
    if (engineStatus == -1)
    {
        cout << "[!] Error: " << pCaptureEngine->getError() << endl;
        return 1;
    }

    cout << "[+] Exiting." << endl;
    return 0;
}

//Do UI on seperate loop for clean pcap cleanup and non blocking loops
void uiLoop()
{
    //Set UI paramaters
    initscr();
    nodelay(stdscr, true);    //No delay for getch()
    cbreak();                 //No terminal line buffering
    noecho();                 //No input echoing
    nonl();                   //Better newline handling
    intrflush(stdscr, false); //Don't flush screen on interupt
    keypad(stdscr, true);     //Allow functional buttons

    //User Interface loop
    while (keepRunning)
    {
        //Make a copy of network connections and sort them by most packets sent
        vector<Network_Connection> cList = pCaptureEngine->getConnectionsList();
        std::sort(cList.begin(), cList.end(), connSort);

        //Use stringstream and string to use iomanip formating with printw()
        string line;
        stringstream lineStream;

        //clear old window
        clear();

        //Print connection list column headers
        lineStream << "#   "
                   << "Type" << "  " << right << setw(15) << "Local Address"
                   << ":" << left << setw(5) << "Port" << "   " << right
                   << setw(15) << "Remote Address" << ":" << left << setw(5)
                   << "Port" << "  " << setw(10) << "Packets" << "  "
                   << "Data";

        //Convert formated stream to a ncurses printable line of output
        line = lineStream.str();
        lineStream.str("");
        printw("%s\n", line.c_str());

        //Create screenbounds safegaurd to prevent pourover
        int maxScrX, maxScrY = 0;
        bool boundsIssue = false;
        getmaxyx(stdscr, maxScrY, maxScrX);

        //Figure out if we need
        if (!cList.empty() && maxScrY > 0 && (static_cast<int>(cList.size()) + 1) > maxScrY)
        {
            boundsIssue = true;
        }

        //Connection number iterator
        int iter = 0;

        //Print connection list
        for (Network_Connection &nconz : cList)
        {
            iter++;

            //Check if reached screen boundry and stop if so
            if (boundsIssue == true && (iter + 1) == maxScrY)
            {
                printw("### Connections Beyond Screen Bounds ###\n");
                break;
            }

            //Print a connection
            lineStream << left << setw(3) << iter << " "
                       << nconz.protocol << "   " << right << setw(15)
                       << nconz.srcIP << ":" << left << setw(5)
                       << nconz.srcPort << "   " << right << setw(15)
                       << nconz.dstIP << ":" << left << setw(5)
                       << nconz.dstPort << "  " << setw(10)
                       << nconz.packetCount << "  "
                       << nconz.dataSent;

            //Convert formated stream to a ncurses printable line of output
            line = lineStream.str();
            lineStream.str("");
            printw("%s\n", line.c_str());
        }

        //Write updated window to screen
        refresh();

        //User control check
        char uInput = '\0';
        uInput = getch();
        
        //Process user control
        switch (uInput)
        {
            //Pause printing of connection list
            case 'p':
            {
                printw("\nOutput Paused");
                refresh();
                 
                uInput = '\0';
            
                while (uInput != 'p' && keepRunning)
                {
                    std::this_thread::sleep_for(milliseconds(111));
                    uInput = getch();
                }

                break;
            }
            //Clear list of connections
            case 'c':
            {
                pCaptureEngine->clearConnectionsList();

                refresh();

                break;
            }
        }
        
        //pre sleep kill switch check
        if (!keepRunning)
        {
            break;
        }

        //Sleep between screen writes
        std::this_thread::sleep_for(milliseconds(111));
    }

    //UI cleanup
    clear();
    refresh();
    endwin();
}

//Handle user interrupts and terminations
void signalHandler(int sigNum)
{
    //Handle user interrupt
    if (sigNum == SIGINT)
    {
        if (pCaptureEngine)
        {
            pCaptureEngine->stopEngine();
        }
    }
    else if (sigNum == SIGQUIT)   //Handle user or system supplied termination
    {
        if (pCaptureEngine)
        {
            pCaptureEngine->stopEngine();
        }
    }
    else if (sigNum == SIGTERM)   //Handle user or system supplied termination
    {
        if (pCaptureEngine)
        {
            pCaptureEngine->stopEngine();
        }
    }
}

void printInterfaceList(vector<string> intList)
{
    cout << "[#] Pcap Devices:\n"
         << "[^]\n";
    
    //Print list of available pcap devices
    for ( string s : intList )
    {
        cout << "[*] " << s << endl;
    }

    cout << "[^]\n";
}

//Sort connection list by multiple directives
bool connSort(const Network_Connection connA, const Network_Connection connB)
{
    //Sort by most packets per connection
    if (connA.packetCount > connB.packetCount)
    {
        return true;
    }
    //Sort secondarily by data sent
    else if (connA.packetCount == connB.packetCount)
    {
        if (connA.dataSent > connB.dataSent)
        {
            return true;
        }
		else if  (connA.dataSent == connB.dataSent)
        {
            if (connA.srcIP < connB.srcIP)
            {
                return true;
            }
		}
    }
    
    return false;
}
