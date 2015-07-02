#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "rmutex.h"

#define min(a,b) ( (a) < (b) ? (a) : (b) )

/* -- gcc specific vararg macro support ... but its so nice! -- */
#ifdef _DEBUG_
#define Debug(x, args...) fprintf(stderr,x, ## args)
#define DebugIP(x) \
  do { struct in_addr addr; addr.s_addr = x; fprintf(stderr,"%s",inet_ntoa(addr));\
     } while(0)
#define DebugMAC(z) \
  do { unsigned char * x = (unsigned char*) z; int ivyl; for(ivyl=0; ivyl<5; ivyl++) fprintf(stderr,"%02x:", \
  (x[ivyl])); fprintf(stderr,"%02x",(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(z) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) fprintf(stderr,"%02x:", \
  (unsigned char)(z[ivyl])); fprintf(stderr,"%02x",(unsigned char)(z[5])); } while (0)
#endif



#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define ARP_TABLE_SIZE 100
#define OUTSTANDING_ARP_LIMIT 10
#define ARP_TIMEOUT 3
#define ARP_ATTEMPTS 5
#define PACKET_TIMEOUT 10
#define ARP_CACHE_RESIDENCY_TIME 30

/** number of uint8_ts in the Ethernet header (dst MAC + src MAC + type) */
#define ETH_HEADER_LEN 14

/** max uint8_ts in the payload (usually 1500B, but jumbo may be larger */
#define ETH_MAX_DATA_LEN 2048

/** max uint8_ts in the Ethernet frame (header + data uint8_ts) */
#define ETH_MAX_LEN (ETH_HEADER_LEN + ETH_MAX_DATA_LEN)

/** min uint8_ts in the Ethernet frame */
#define ETH_MIN_LEN 60

#define IPV4_HEADER_LEN 20  


/* forward declare */
struct sr_if;
struct sr_rt;

/* struct arptable_entry
 * (ethaddr, ipaddr) pairs and unix timestamp of expiration
 */

struct arptable_entry{
    uint32_t ipaddr;
    addr_mac_t ethaddr;
    time_t expiry;
};

/* packets which are ready to send but don't have dst MAC addresses
 * back from arp replies yet */
struct pending_packet_queue_entry{
    uint8_t * payload;
    char * iface;
    unsigned payload_len;
    time_t expiry;
    uint32_t ip;
};

/* outstanding arp queries - keeps from sending multiple ARPs 
 * for multiple packets */

struct arp_response_queue_entry{
    uint32_t ip;
    char * iface;
    time_t expiry;
    int req_remaining;
};

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
    struct arptable_entry arptable[ARP_TABLE_SIZE];
    rmutex_t arptable_lock;
    rmutex_t arp_queue_lock;
    struct arp_response_queue_entry aq[OUTSTANDING_ARP_LIMIT];
    struct pending_packet_queue_entry pq[OUTSTANDING_ARP_LIMIT];
};

void *  arp_queue_caretaker(void * router);

struct arphdr_eth
  {
    unsigned short int ar_hrd;      /* Format of hardware address.  */
    unsigned short int ar_pro;      /* Format of protocol address.  */
    unsigned char ar_hln;       /* Length of hardware address.  */
    unsigned char ar_pln;       /* Length of protocol address.  */
    unsigned short int ar_op;       /* ARP opcode (command).  */
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char ar_sha[ETHER_ADDR_LEN];   /* Sender hardware address.  */
    unsigned char ar_sip[4];      /* Sender IP address.  */
    unsigned char ar_tha[ETHER_ADDR_LEN];   /* Target hardware address.  */
    unsigned char ar_tip[4];      /* Target IP address.  */
  };


/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );

/* called whenever a packet is received */
void sr_handlepacket(struct sr_instance* , uint8_t * payload, unsigned int length, char* interface );

/* helper function to determine if an ethernet frame is addressed to a given
 * interface's MAC address
 */
int ether_to_me(addr_mac_t * router_address, addr_mac_t * prospective_address);

/* call this to route/consume an ip packet */
int handle_ip(struct sr_instance *, uint8_t * ,unsigned int,char *);
/* call this to consume an ARP packet */
int handle_arp(struct sr_instance *, uint8_t * ,unsigned int,char *);
/* call this to compute and set the ip header checksum */
uint16_t checksum_ip( struct ip * hdr );
/* call this to compute a checksum over len bites starting at buf */
uint16_t checksum( uint16_t* buf, unsigned len);
/* call this to compute and set an icmp checksum */
uint16_t checksum_icmp( hdr_icmp_t* , unsigned  ) ;
/* call this to determine whether an ip is destined for any of the router's
 * interfaces' addresses
 */
int ip_to_me(struct sr_instance * , uint32_t );
/* call this to construct and send an ICMP packet */
void icmp_send(struct sr_instance * router,
                uint32_t dst,
                uint32_t src,
                uint8_t * ip_packet,
                unsigned len,
                uint8_t type,
                uint8_t code,
                uint16_t extra1,
                uint16_t extra2 );

/* call this to consume an ICMP packet destined for this router */
void icmp_handle_packet( struct sr_instance * router, uint8_t* ip_packet, unsigned len );

/* 
 * call this to create and send an IP packet (for this router, this will
 * mainly be used to send ICMP packets)
 */
int  network_send_packet_from( struct sr_instance *,
                          uint32_t dst,
                          uint32_t src,
                          uint8_t proto,
                          uint8_t* buf,
                          unsigned len );

/* 
 * call this to send an IP packet when the outbound address & interface
 * are not known - requires checking routing table
 */
int network_send_packet(struct sr_instance * router,
                     uint32_t dst,
                     uint8_t proto,
                     uint8_t* payload,
                     unsigned len );

/*
 * determine the route via the outbound ip and then queue the
 * ethernet frame for sending
 */
int router_send_ethernet_frame( struct sr_instance * router,
                                 uint32_t dst_ip,
                                 uint16_t type,
                                 uint8_t* payload,
                                 unsigned len );

/* 
 * given a next hop routing decision and an outbound interface, 
 * construct an ethernet packet to the correct MAC address - 
 * if this exists in the cache the packet can be sent immediately,
 * otherwise it must be queued while the ARP cache resolves the
 * next hop IP address's MAC address.
 */
int  router_queue_ethernet_frame(struct sr_instance * router,
                                     struct sr_rt * rti,
                                     struct sr_if * intf,
                                     uint16_t type,
                                     uint8_t* payload,
                                     unsigned payload_len ) ;

/* 
 * upon receipt of an arp reply, save the (ip,mac) mapping
 * to the arp cache.
 */
int arp_table_set_entry(struct sr_instance * sr, uint32_t ip, addr_mac_t macaddr);

/*
 * given ip address ip, find the (ip,mac) mapping if it exists in the cache,
 * and set macaddr to the correct value.
 */
int arp_table_get_entry(struct sr_instance * sr, uint32_t ip, addr_mac_t * macaddr);

/*
 * given an IP address, find the next hop routing decision's routing table
 * entry
 */
struct sr_rt * rtable_find_route(struct sr_instance * sr, uint32_t ip);

/* arp cache miss - queue this packet if possible, and send an arp request
 * to find the destination IP's MAC if necessary.
 */
void queue_ethernet_wait_arp(struct sr_instance * sr,
                                     struct sr_rt * rti,
                                     struct sr_if * intf,
                                     uint16_t type,
                                     uint8_t* payload,
                                     unsigned payload_len );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
