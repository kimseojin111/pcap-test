LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.c libnet-headers.h

clean:
	rm -f pcap-test *.o
