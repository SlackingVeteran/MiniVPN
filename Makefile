all:
	gcc -o vpnserver vpnserver.c -lssl -lcrypto -lcrypt
	gcc -o vpnclient vpnclient.c -lssl -lcrypto -lcrypt

clean:
	rm Server Client Server
