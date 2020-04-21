#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <termios.h>

#define CHK_SSL(err) if((err) < 1) {ERR_print_errors_fp(stderr); printf("Error detected");exit(2);}
#define CA_DIR "./CA_DIR"

#define BUFF_SIZE 2000
#define PORT_NUMBER 4433
#define SERVER_IP "10.0.2.5"
struct sockaddr_in peerAddr;

//-------------< Verify Call back >---------------
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  char  buf[300];

  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
  printf("subject= %s\n", buf);

  if (preverify_ok == 1) {
    printf("Verification passed.\n");
  }
  else {
    int err = X509_STORE_CTX_get_error(x509_ctx);
    printf("Verification failed: %s.\n",
    X509_verify_cert_error_string(err));exit(2);
  }
}

//-----------< Create Tun Device >------------
int createTunDevice() {
  int tunfd, err;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  //-------------< oprning a tun device and registering it with usage of ioctl api >-------------
  tunfd = open("/dev/net/tun", O_RDWR);
  //--------< Added error cheching while opening tun device >-------------
  if ((err = ioctl(tunfd, TUNSETIFF, (void *)&ifr)) < 0) {
    perror("ioctl(TUNSETIFF)");
    close(tunfd);
    return err;
  }
  return tunfd;
}

//----------------< TCPClient >--------------

int setupTCPClient(const char* hostname, int port) {
  struct sockaddr_in server_addr;
  struct hostent* hp = gethostbyname(hostname);

  // Create a TCP socket
  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // Fill in the destination information (IP, port #, and family)
  memset(&server_addr, '\0', sizeof(server_addr));
  memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
  server_addr.sin_port = htons(PORT_NUMBER);
  server_addr.sin_family = AF_INET;

  // Connect to the destination
  connect(sockfd, (struct sockaddr*) &server_addr,
  sizeof(server_addr));

  return sockfd;
}

//----------< The parent process monitoring for the tunnel's data >---------------
void tunSelected(int tunfd, int sockfd, SSL *ssl) {
  int  len;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  if (len < 0){
    perror("Reading Data");
    exit(1);
  }
  SSL_write(ssl, buff, len);
}

//---------< Socket interface selected >--------
void socketSelected(int tunfd, int sockfd, SSL *ssl) {
  int  len;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  len = SSL_read(ssl, buff, BUFF_SIZE);
  write(tunfd, buff, len);
}

//----------< Login Check For the Task #5 >----------
char *getpass(const char *ptr);

int verifyClient(SSL *ssl) {
  unsigned char username[50];
  unsigned char credentials[100];
  char buff[BUFF_SIZE];
  int err;

  printf("ENTER USERNAME : ");
  scanf("%s", username);
  username[strlen(username)] = '\0';
  char *password;
  char *success = "suucessful";
  password = getpass("type in your password: ");
  int i = 0;
  for (i = 0; username[i] != '\0'; i++)
  credentials[i] = username[i];
  credentials[i] = '@';
  int ptr = i + 1;
  for (i = 0; password[i] != '\0'; i++)
  credentials[ptr + i] = password[i];

  credentials[ptr + i] = '\0';

  SSL_write(ssl, credentials, sizeof(credentials));

  int l = SSL_read(ssl, buff,BUFF_SIZE);
  buff[l] = '\0';
  //printf("Buffer recieved is %s", buff);
  char *succ = strtok(buff, "@");
  char *ip = strtok(NULL,"@");

  if (strcmp(buff, "invalid") == 0){
    printf("\nAuthentication Failed");
    SSL_shutdown(ssl);
    SSL_free(ssl);

    return 0;
  }
  else{
    printf("Valid User");
    FILE *fp = fopen("./Clientconfig.sh","w");
    fprintf(fp,"set -o xtrace\n");
    fprintf(fp,"sudo ifconfig tun0 %s/24 up\n",ip);
    fprintf(fp,"sudo route add -net 192.168.60.0/24 tun0\n");
    fprintf(fp,"route -n");
    fclose(fp);
    system("sudo sh Clientconfig.sh");
  }
  return 1;
}
//---------< SSL connection setup >------------
SSL* setupTLSClient(const char* hostname){
  // Step 0: OpenSSL library initialization
  // This step is no longer needed as of version 1.1.0.
  printf("%s",hostname);
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL* ssl;

  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,NULL);
  if (SSL_CTX_load_verify_locations(ctx, NULL, "./ca_client") < 1) {
    printf("Error setting the verify locations. \n");
    exit(0);
  }
  ssl = SSL_new(ctx);

  X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
  X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

  return ssl;
}

int main(int argc, char *argv[]) {
  printf("Hello");
  char *hostname = "hello.com";
  int port = 443, clientAuth;
  if (argc > 1) hostname = argv[1];
  if(argc > 2)  port = atoi(argv[2]);
  printf("%s",hostname);
  /*----------------TLS initialization ----------------*/
  SSL *ssl = setupTLSClient(hostname);

  int tunfd, sockfd;

  //--------< Initilaize tun/tap device >---------------
  if ((tunfd = createTunDevice()) < 0){
    printf("Error");
    perror("Error connecting to tun/tap device interface");
    exit(1);
  }
  /*----------------TLS handshake ---------------------*/


  sockfd = setupTCPClient(hostname, port);
  if (sockfd < 0) printf("Socket error");

  SSL_set_fd(ssl, sockfd);
  int err = SSL_connect(ssl); CHK_SSL(err);
  printf("\nSSL connection is successful\n");
  printf("\nSSL connection using %s\n", SSL_get_cipher(ssl));
  if(port!=443){
    clientAuth = verifyClient(ssl);
    if (clientAuth == 1) {
      printf("\nClient Authentication Successfull");

      while (1) {
        fd_set readFDSet;
        int ret;
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);

        ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (ret < 0 && errno == EINTR)
        continue;
        if (ret < 0) {
          printf("Select error");
          perror("Select()");
          exit(1);
        }

        if (FD_ISSET(tunfd, &readFDSet)) { tunSelected(tunfd, sockfd, ssl); }
        if (FD_ISSET(sockfd, &readFDSet)) { socketSelected(tunfd, sockfd, ssl); }

      }
    }
    else{
      printf("\nEnter valid credentials\n");
      SSL_shutdown(ssl);
      SSL_free(ssl);

      close(sockfd);

      exit(1);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);

    close(sockfd);
  }

}
