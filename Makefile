CC=cl
SRC=serv.c dns.c ini.c parse_config.c blacklist.c
TARGET=serv

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) ws2_32.lib
	del *.obj