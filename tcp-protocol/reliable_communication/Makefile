TARGETS=sender receiver proxy

all: $(TARGETS)

hw5_sender: sender.c tcp.c
	gcc --std=gnu99 -o sender sender.c tcp.c

hw5_receiver: receiver.c tcp.c
	gcc --std=gnu99 -o receiver receiver.c tcp.c

proxy: proxy.c
	gcc --std=gnu99 -g -o proxy proxy.c

clean:
	rm -f $(TARGETS)

