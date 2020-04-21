all:
	gcc -o Server vpnserver.c
	gcc -o Client vpnclient.c

clean:
	rm Server Client Server
