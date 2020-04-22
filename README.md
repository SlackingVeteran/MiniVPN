# MiniVPN
VPN with MultiClient and Authentication Support

--------------------------
Directory setup for keys
--------------------------
* `mkdir cert_server`
* `cd cert_server`
* `mkdir demoCA`
* `mkdir demoCA/newcerts`
* `touch demoCA/index.txt demoCA/serial`
* `echo 1000 > demoCA/serial`

--------------------------
Creating pair of keys for CA using "openssl":
--------------------------
`openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -keyout CA_key.pem -out CA_Cert.pem`

--------------------------
Generate public/private Key Pair for your own domain example "yourname.com":
--------------------------
`openssl genrsa -aes128 -out yourname_key.pem 2048`

--------------------------
Generate certificate signing request:
--------------------------
`openssl req -new -key yourname_key.pem -out yourname.csr -sha256`

--------------------------
CA Sign:
--------------------------
`openssl ca -in yourname.csr -out yourname_cert.pem -md sha256 -cert CA_Cert.pem -keyfile CA_Key.pem`

--------------------------
Build the VPN:
--------------------------
`make`

--------------------------
Run the server: 
--------------------------
`sudo ./vpnserver`

--------------------------
Assign IP to VPN SERVER TUN Device:
--------------------------
`sudo ifconfig tun0 192.168.59.1/24 up`

--------------------------
Enable ip forwarding:
--------------------------
`sudo sysctl net.ipv4.ip_forward=1`

--------------------------
Run the client: 
--------------------------
First change the SERVER_IP in vpnclient.c to match with the server's ip.  
`sudo ./vpnclient hostname port`

--------------------------
Note:
--------------------------
You also need to configure the TUN interface server side, client side is configured automatically
and set up routings. See the lab description for instructions.
