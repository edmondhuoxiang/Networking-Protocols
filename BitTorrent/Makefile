OBJECTS=bencode-tools-2011-03-15/bencode.o
INCLUDES=bencode-tools-2011-03-15/include/ 

all:
	echo "Don't forget to install OpenSSL and libcurl3-dev"
	gcc -g --std=gnu99 -I $(INCLUDES) BitTorrent_client.c bencode.c $(OBJECTS) -o BitTorrent_client -lssl -lcurl 
