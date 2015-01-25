/****************************************************************************/
/* garpd - A lightweight gratuitous ARP reporting daemon.                   */
/****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>

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


int main()
{
    int sck;

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
        /* message. Later on we'll add a UNIX socket.                       */
        /********************************************************************/
        printf(
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
    }
}
