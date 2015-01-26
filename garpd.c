/****************************************************************************/
/* garpd - A lightweight gratuitous ARP reporting daemon.                   */
/****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>

#define UNIX_SCK_PATH "/var/opt/test.sck"

/****************************************************************************/
/* This structure represents a single ARP packet. It's used to allow named  */
/* field access later in the program.                                       */
/****************************************************************************/
typedef struct arp_pkt {
  unsigned short arp_hrd;
  unsigned short arp_pro;
  unsigned char arp_hln;
  unsigned char arp_pln;
  unsigned short arp_op;
  unsigned char arp_sha[6];
  unsigned char arp_spa[4];
  unsigned char arp_tha[6];
  unsigned char arp_tpa[4];
} arp_pkt_t;


/*****************************************************************************/
/* Creates a Unix domain socket and listens for a connection on it. In this  */
/* early prototype, only listens for one connection: multiple not allowed.   */
/*****************************************************************************/
int create_unix_socket(const char *sockname,
                       unsigned int namelen,
                       int *unix_sck)
{
    int connection;
    int remote_size;
    struct sockaddr_un sockdata;
    struct sockaddr_un remotedata;

    /*************************************************************************/
    /* For now, the Unix socket is a stream socket that sends the data       */
    /* newline-terminated. In future we may want to make this a datagram     */
    /* socket instead.                                                       */
    /*************************************************************************/
    if ((*unix_sck = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("cannot create unix socket");
        exit(1);
    }

    /*************************************************************************/
    /* Set up the Unix socket to the chosen path. If one is already there,   */
    /* remove it.                                                            */
    /*************************************************************************/
    sockdata.sun_family = AF_UNIX;
    strncpy(sockdata.sun_path, sockname, namelen);
    sockdata.sun_path[namelen] = '\0';

    unlink(sockdata.sun_path);

    /*************************************************************************/
    /* Bind and listen.                                                      */
    /*************************************************************************/
    if ((bind(*unix_sck, (struct sockaddr *)&sockdata, sizeof(sockdata))) < 0) {
        perror("cannot bind unix socket");
        exit(1);
    }

    if ((listen(*unix_sck, 1)) < 0) {
        perror("cannot listen on unix socket");
        exit(1);
    }

    /*************************************************************************/
    /* In this early iteration, only ever accept one connection.             */
    /* TODO: Fix this up.                                                    */
    /*************************************************************************/
    remote_size = sizeof(struct sockaddr_un);
    connection = accept(*unix_sck, (struct sockaddr *)&remotedata, &remote_size);

    if (connection < 0) {
        perror("error accepting unix socket connection");
        exit(1);
    }

    return connection;
}


int main()
{
    int sck;
    int unix_listen_sck;
    int unix_connection;

    char output_buffer[2000];
    int output_len;

    /************************************************************************/
    /* buffer is used as a temporary storage location for each ARP packet.  */
    /* It is large enough to fit your average MTU: we should fix this to    */
    /* find the largest MTU on the machine to ensure it fits.               */
    /*                                                                      */
    /* The packet variable is a simple index into the buffer (skipping the  */
    /* constant-size Ethernet header.                                       */
    /************************************************************************/
    char buffer[2000];
    arp_pkt_t *packet = (arp_pkt_t *)(buffer + 14);

    /************************************************************************/
    /* Create a raw ARP socket.                                             */
    /************************************************************************/
    if ((sck = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("cannot create socket");
        exit(1);
    }

    /************************************************************************/
    /* Create a unix socket.                                                */
    /************************************************************************/
    unix_connection = create_unix_socket(UNIX_SCK_PATH,
                                         strlen(UNIX_SCK_PATH),
                                         &unix_listen_sck);

    /************************************************************************/
    /* In this early version, just spin over the socket until we hit an     */
    /* error.                                                               */
    /************************************************************************/
    while (recv(sck, buffer, sizeof(buffer), 0))
    {
        /********************************************************************/
        /* Sanity check: I have no reason to believe this isn't an ARP      */
        /* packet, but let's confirm that it is.                            */
        /********************************************************************/
        if ((((buffer[12]) << 8) + buffer[13]) != ETH_P_ARP) continue;

        /********************************************************************/
        /* This is a gratuitous ARP packet if the SPA and TPA are the       */
        /* same. The SHA is then set to the MAC to associate with the IP.   */
        /********************************************************************/
        if (memcmp(packet->arp_spa, packet->arp_tpa, sizeof(packet->arp_spa)))
            continue;

        /********************************************************************/
        /* This is a GARP. For now, just print the IP and MAC from the      */
        /* message.                                                         */
        /********************************************************************/
        output_len = snprintf(
            output_buffer,
            sizeof(output_buffer),
            "%u.%u.%u.%u @ %02x:%02x:%02x:%02x:%02x:%02x\n",
            packet->arp_spa[0],
            packet->arp_spa[1],
            packet->arp_spa[2],
            packet->arp_spa[3],
            packet->arp_sha[0],
            packet->arp_sha[1],
            packet->arp_sha[2],
            packet->arp_sha[3],
            packet->arp_sha[4],
            packet->arp_sha[5]
        );

        send(unix_connection, output_buffer, output_len, 0);
    }

    close(unix_connection);
    close(unix_listen_sck);
    unlink(UNIX_SCK_PATH);

    return 0;
}
