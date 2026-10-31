CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LIBS = -lcrypto

all: crypto_test sender receiver relay sniffer

crypto_test:
	$(CC) $(CFLAGS) src/main.c src/crypto.c src/handshake.c src/kdf.c -o crypto_test $(LIBS)

sender:
	$(CC) $(CFLAGS) src/sender.c src/crypto.c src/handshake.c src/kdf.c -o sender $(LIBS)

receiver:
	$(CC) $(CFLAGS) src/receiver.c src/crypto.c src/handshake.c src/kdf.c -o receiver $(LIBS)

relay:
	$(CC) $(CFLAGS) src/relay.c -o relay

sniffer:
	$(CC) $(CFLAGS) src/sniffer.c -o sniffer -lpcap

clean:
	rm -f crypto_test sender receiver relay sniffer
