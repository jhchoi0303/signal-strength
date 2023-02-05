LDLIBS=-lpcap

all: signal-strength

signal-strength: signal-strength.o net_address.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f signal-strength *.o