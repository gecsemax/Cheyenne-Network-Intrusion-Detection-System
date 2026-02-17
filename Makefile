CC = gcc
CFLAGS = -O2 -Wall -pthread
LIBS = -lpcap -lnetfilter_queue   # add -lpfring later if you install PF_RING

TARGET = cheyenne_nids

all: $(TARGET)

$(TARGET): nids.c
	$(CC) $(CFLAGS) -o $(TARGET) nids.c $(LIBS)

clean:
	rm -f $(TARGET)
