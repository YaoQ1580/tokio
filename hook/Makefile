CXX ?= g++
INCLUDE_DIRS := -I/usr/local/include
CXXFLAGS ?= -fPIC -shared -std=c++17 -O2 -Wall $(INCLUDE_DIRS)

TARGET  := libhook.so
SRCS    := hook.cc
HDRS    := hook.h

LIBS := /usr/local/lib/libfstack.a -ldl

# Installation directories (override with `make PREFIX=/custom`)
PREFIX ?= /usr/local
DESTDIR ?=
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

# Declare phony targets  
.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET) *.o 

install: $(TARGET)
	# Create destination directories if they don't exist
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	# Copy shared library and headers with appropriate permissions
	install -m 0755 $(TARGET) $(DESTDIR)$(LIBDIR)
	install -m 0644 $(HDRS) $(DESTDIR)$(INCLUDEDIR) 