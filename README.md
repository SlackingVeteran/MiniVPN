# MiniVPN
VPN with MultiClient Support

--------------------------
To run the server: 
--------------------------
$ sudo ./vpnserver


--------------------------
To run the client: 
--------------------------

First change the SERVER_IP in vpnclient.c to match with the server's ip.  
$ sudo ./vpnclient

Note: You also need to configure the TUN interfaces on both sides
and set up routings. See the lab description for instructions.
