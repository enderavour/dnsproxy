CC = gcc
SRC = dproxy.c dns.c blacklist.c parse_config.c 
TARGET = dproxy

all: $(TARGET)

$(TARGET): $(SRC)
    $(CC) -o $(TARGET) $(SRC)
