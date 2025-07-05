CXX ?= g++
CXXFLAGS ?= -fPIC -shared -std=c++17 -O2 -Wall

TARGET  := libhook.so
SRCS    := hook/hook.cc
HDRS    := hook/hook.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) -ldl

clean:
	rm -f $(TARGET) *.o 