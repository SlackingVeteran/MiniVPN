all:
	gcc -o Server vpnserver.c -lssl -lcrypto -lcrypt
	gcc -o Client vpnclient.c -lssl -lcrypto -lcrypt

clean:
	rm Server Client Server
