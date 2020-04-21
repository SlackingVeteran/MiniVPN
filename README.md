# MiniVPN
VPN with MultiClient and Authentication Support

--------------------------
To run the server: 
--------------------------
$ sudo ./vpnserver


--------------------------
To run the client: 
--------------------------

First change the SERVER_IP in vpnclient.c to match with the server's ip.  
$ sudo ./vpnclient hostname port

Note: You also need to configure the TUN interface server side, client side is configured automatically
and set up routings. See the lab description for instructions.
