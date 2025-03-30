CXX = g++
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -lpcap

SRCS = src/main.cpp src/capturingPackets.cpp
OBJS = $(SRCS:.cpp=.o)

TARGET = capture_packets

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
