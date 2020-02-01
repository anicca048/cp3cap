
CXX=g++
SECFLAGS=-D_FORTIFY_SOURCE=2 -fstack-protector -fPIE -pie -Wl,-z,relro,-z,now
CXXFLAGS=-std=c++14 -O2 -pipe -Wall -Wextra $(SECFLAGS)
LDFLAGS=-Wall -Wextra -Wl,--build-id=none $(SECFLAGS)
LDLIBS=-lpcap -lpthread -lncurses

SRCS=CP3cap.cpp CaptureEngine.cpp CaptureSession.cpp
OBJS=$(subst .cpp,.o,$(SRCS))
BINS=cp3cap

all : cp3cap

cp3cap : $(OBJS)
	$(CXX) $(LDFLAGS) -o cp3cap $(OBJS) $(LDLIBS)
	strip -s -R .comment $(BINS)

CP3cap.o : CP3cap.cpp CaptureEngine.h
	$(CXX) $(CXXFLAGS) -c -o CP3cap.o CP3cap.cpp

CaptureEngine.o : CaptureEngine.cpp CaptureEngine.h CaptureSession.h
	$(CXX) $(CXXFLAGS) -c -o CaptureEngine.o CaptureEngine.cpp

CaptureSession.o : CaptureSession.cpp CaptureSession.h Packets.h
	$(CXX) $(CXXFLAGS) -c -o CaptureSession.o CaptureSession.cpp

clean :
	rm -f $(BINS) $(OBJS)
