CC = g++
CPPFLAGS = -std=c++11 -fPIC -O2 -fstack-protector-all
CPPFLAGS += -Iinclude -I/usr/include/nss -I/usr/include/nspr
LDFLAGS = -shared

TARGET = libmozpix.so

SOURCES = $(shell echo lib/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CPPFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	@rm $(TARGET) $(OBJECTS)
