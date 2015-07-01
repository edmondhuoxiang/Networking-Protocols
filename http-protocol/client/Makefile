BINARIES=http_client 

all: $(BINARIES)

clean:
	rm $(BINARIES)

$*: $@.c
	gcc -g -o $@ $?

