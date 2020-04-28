# For building a non-release (debug) build, comment out SECFLAGS and strip
# 	lines, and uncomment DEBUGFLAGS line.

CXX=g++
SECFLAGS=-D_FORTIFY_SOURCE=2 -fstack-protector -fPIE -pie -Wl,-z,relro,-z,now
#DEGUBFLAGS=-g
CXXFLAGS=$(DEGUBFLAGS) -std=c++17 -O2 -pipe -Wall -Wextra $(SECFLAGS)
LDFLAGS=-Wall -Wextra -Wl,--build-id=none $(SECFLAGS)
LDLIBS=-lpcap -lpthread -lncurses

SRCS=CP3cap.cpp Connections.cpp Shim.cpp
OBJS=$(subst .cpp,.o,$(SRCS))
BINS=cp3cap

all : cp3cap

cp3cap : $(OBJS)
	$(CXX) $(LDFLAGS) -o cp3cap $(OBJS) $(LDLIBS)
	strip -s -R .comment $(BINS)

CP3cap.o : CP3cap.cpp Connections.h Shim.h
	$(CXX) $(CXXFLAGS) -c -o CP3cap.o CP3cap.cpp

Connections.o : Connections.cpp Connections.h Shim.h
	$(CXX) $(CXXFLAGS) -c -o Connections.o Connections.cpp

Shiim.o : Shim.cpp Shim.h Packets.h
	$(CXX) $(CXXFLAGS) -c -o Shim.o Shim.cpp

clean :
	rm -f $(BINS) $(OBJS)
