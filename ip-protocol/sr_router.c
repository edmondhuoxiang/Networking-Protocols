/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "rmutex.h"
#include "arp_caretaker.c"

int TOME=0;
int REPING=0;
uint16_t ipid;
int TIMEOUT=0;
int UNREACH=0;
/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    pthread_t tid;
    /* REQUIRES */
    assert(sr);
    
    // init arp cache

    memset(&sr->arptable,0,ARP_TABLE_SIZE*sizeof(struct arptable_entry));
    memset(&sr->pq,0,OUTSTANDING_ARP_LIMIT * sizeof(struct pending_packet_queue_entry));
    memset(&sr->aq,0,OUTSTANDING_ARP_LIMIT * sizeof(struct arp_response_queue_entry));
    rmutex_init(&sr->arptable_lock);
    rmutex_init(&sr->arp_queue_lock);
    pthread_create(&tid,NULL,arp_queue_caretaker,(void *) sr);

} /* -- sr_init -- */

/* Method: ether_to_me:
 * returns true if i should process this ethernet packet
 * (if it is to this address or to broadcast)
 */
int ether_to_me(addr_mac_t  * my_address, addr_mac_t * addr_s){
    unsigned char * addr = (unsigned char *)addr_s;
    return ((memcmp(my_address,addr_s,ETHER_ADDR_LEN)==0) ||
          ((addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff));
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/


void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	TOME=0;
	TIMEOUT=0;
	UNREACH=0;
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d on interface %s \n",len, interface);

	struct sr_ethernet_hdr * eth_header;
	eth_header = (struct sr_ethernet_hdr *)packet;
	if(ntohs(eth_header->ether_type)==ETHERTYPE_ARP)
	{
		printf("*** -> This is an ARP packet\n");
		//handle_arp(sr,packet+sizeof(struct sr_ethernet_hdr), len-sizeof(struct sr_ethernet_hdr),interface);
		handle_arp(sr,packet, len,interface);
	}
	else if(ntohs(eth_header->ether_type)==ETHERTYPE_IP)
	{
		printf("*** -> This is an IP packet\n"); 
		handle_ip(sr,packet,len,interface);
	}
    /* must have at least an Ethernet header but not too big either */
    // TODO: 
    // verify that the ethernet frame has a valid length
    // drop the packet if it does not apply to this interface
    // determine whether the packet is IP or ARP, and if so,
    // handle the payload with handle_ip() and handle_arp(), respectively
    // if the packet is neither IP nor ARP, drop.
		//
		// use sr_get_interface()->addr to get the mac address of your ethernet interface


}/* end sr_ForwardPacket */

/* this is either an arp request and we are 
 * responsible for replying with our ethernet address
 * or this is an arp reply hopefully to a request
 * we have sent out, in which case we add the entry
 * to our cache.
 */
int handle_arp(struct sr_instance * sr, uint8_t * packet, unsigned int len, char * interface)
{
    struct sr_arphdr * arp_header;
    arp_header = (struct sr_arphdr *) (packet+sizeof(struct sr_ethernet_hdr));
	//unsigned int length = len - sizeof(struct sr_ethernet_hdr);
    uint32_t this_interface_ip;
    // request or reply?
    switch (ntohs(arp_header->ar_op))
    {
        case ARP_REQUEST:
            // TODO:
            // handle this ARP request by sending a reply if necessary.
            // This will entail:
            // verify that the request is for the correct interface
            // allocate space to store the response
            // set the fields in the ethernet header
            // set the fields in the arp header
            // call sr_send_packet() with the correct buffer, packet length,
            //      and interface

			printf("Receive an ARP_REQUEST packet\n");
			this_interface_ip = sr_get_interface(sr,interface)->ip;
			if(this_interface_ip == arp_header->ar_tip)
			{
				printf("This is an ARP_REQUEST to %s \n", interface);
				uint8_t * reply_packet;
				reply_packet = (uint8_t *)malloc(sizeof(uint8_t)*len+1);
				memcpy(reply_packet,packet,len);
				
				uint8_t buffer[ETHER_ADDR_LEN];
				struct sr_arphdr * arp_buf;
				struct sr_ethernet_hdr * ether_buf;
				ether_buf = (struct sr_ethernet_hdr *) reply_packet;
				arp_buf = (struct sr_arphdr *) (reply_packet+sizeof(struct sr_ethernet_hdr));


				memcpy(buffer, sr_get_interface(sr,interface)->addr.octet, ETHER_ADDR_LEN);
				//set the flieds in the ethernet header
				//memcpy(buffer, ether_buf->ether_dhost.octet, ETHER_ADDR_LEN);
				memcpy(ether_buf->ether_dhost.octet,ether_buf->ether_shost.octet,ETHER_ADDR_LEN);
				memcpy(ether_buf->ether_shost.octet,buffer,ETHER_ADDR_LEN);

				//set the fields in the arp header
				arp_buf->ar_op = htons(ARP_REPLY);

				uint32_t ip_buf;
				ip_buf=arp_buf->ar_sip;
				arp_buf->ar_sip=arp_buf->ar_tip;
				arp_buf->ar_tip=ip_buf;

				memcpy(arp_buf->ar_tha.octet,arp_buf->ar_sha.octet,ETHER_ADDR_LEN);
				memcpy(arp_buf->ar_sha.octet,sr_get_interface(sr,interface)->addr.octet,ETHER_ADDR_LEN);

				sr_send_packet(sr,reply_packet,len,interface);
			}
			else
			{
				printf("This is NOT an ARP_REQUEST to me\n");
			}
            break;
        case ARP_REPLY:
            // store the arp reply in the router's arp cache

			printf("This is an ARP_REPLY\n");
            arp_table_set_entry(sr,arp_header->ar_sip,arp_header->ar_sha);
            break;
        default:
            Debug("dropping unhandleable ARP packet\n");
    }
    return 0;
}

int handle_ip(struct sr_instance *sr, uint8_t * packet,unsigned int len,char * interface)
{

	REPING=0;
	struct sr_ethernet_hdr * ether_hdr=(struct sr_ethernet_hdr *)packet;
    struct ip * hdr = (struct ip *)(packet+sizeof(struct sr_ethernet_hdr));
    // TODO: 
    // verify the incoming IP packet is well formed.
    
    uint16_t orginal_sum = hdr->ip_sum;
	checksum_ip(hdr);
	if(orginal_sum != hdr->ip_sum)
		//printf("This is a valid ip packet\n");
	//else
	{
		printf("This is an invalid ip packet, drop it.\n");
		return 1;
	}

    // TODO: handle packets to this router: the only packets specifically
    // addressed to this router that you should respond to are ICMP Ping
    // messages. All data packets should receive an error response stating
    // that the protocol is unreachable.
	

		if(hdr->ip_p!=IPPROTO_ICMP)
		{
			printf("Not a ICMP packet, drop it.%d\n", hdr->ip_p);
			UNREACH=1;
			icmp_handle_packet(sr,hdr,len-sizeof(struct sr_ethernet_hdr));
		}
		else if(hdr->ip_ttl==1)
		{
			//printf("******This is a time out packet !\n");
			TIMEOUT=1;
			icmp_handle_packet(sr,hdr,len-sizeof(struct sr_ethernet_hdr));
		}
		else if(strcmp(inet_ntoa(hdr->ip_dst),"171.67.238.104")==0)
		{

			TOME=1;
			
			//printf("This is a packet for me, TTL=%d\n",hdr->ip_ttl);


			//printf("hl: %x\n",hdr->ip_hl);
			//printf("version: %x\n",hdr->ip_v);
			//printf("type of service: %x\n",hdr->ip_tos);
			//printf("length: %d\n",hdr->ip_len);
			//printf("id: %d\n",hdr->ip_id);
			//printf("off: %d\n",hdr->ip_off);
			//printf("ttl: %d\n",hdr->ip_ttl);
			//printf("protocal: %d\n",hdr->ip_p);
			


			ipid=hdr->ip_id;

			//Change ether address
			
			printf("%d\n",len-sizeof(struct sr_ethernet_hdr));

			icmp_handle_packet(sr, hdr, len-sizeof(struct sr_ethernet_hdr));
/*			icmp_change_type(sr,hdr,len-sizeof(struct sr_ethernet_hdr));
			
			//hdr_icmp_t* icmp_hdr;
			//icmp_hdr = (hdr_icmp_t*)(hdr + IPV4_HEADER_LEN);

			//printf("type: %d\nip: %d\n icmp: %d\n", icmp_hdr->type, (int)hdr, (int)icmp_hdr);
			
			uint8_t tmp[ETHER_ADDR_LEN];

			memcpy(tmp,ether_hdr->ether_dhost.octet, ETHER_ADDR_LEN);
			memcpy(ether_hdr->ether_dhost.octet,ether_hdr->ether_shost.octet,ETHER_ADDR_LEN);
			memcpy(ether_hdr->ether_shost.octet,tmp,ETHER_ADDR_LEN);

			//Change IP address
			uint8_t * buf = (uint8_t *)malloc(sizeof(struct in_addr));

			memcpy(buf, &(hdr->ip_src), sizeof(struct in_addr));
			memcpy(&(hdr->ip_src),&(hdr->ip_dst), sizeof(struct in_addr));
			memcpy(&(hdr->ip_dst),buf,sizeof(struct in_addr));


			//printf("type %d\n",icmp_hdr->type);
			//icmp_hdr->type= htons(ICMP_TYPE_ECHO_REPLY);
			//check sum
			//printf("type %d\n",icmp_hdr->type);
			unsigned int len_icmp = len-sizeof(struct sr_ethernet_hdr)-sizeof(struct ip);
			//icmp_hdr->sum = 0;
			//uint16_t sum = checksum((uint16_t *)icmp_hdr,len_icmp);
			//icmp_hdr->sum = sum;

			checksum_ip(hdr);

			sr_send_packet(sr,packet,len,interface);*/






		}
		else
		{
			if(strcmp(interface,"eth0")!=0)
				REPING=1;
			printf("%s\n", inet_ntoa(hdr->ip_dst));
			if(!router_send_ethernet_frame(sr,hdr->ip_dst.s_addr,htons(ETHERTYPE_IP),
						hdr,len-sizeof(struct sr_ethernet_hdr)))
			{
				Debug("Couldn't find a route to forward IP packet\n");
				
				// TODO: send an ICMP DESTINATION UNREACHABLE
				UNREACH=1;
				icmp_handle_packet(sr,hdr,len-sizeof(struct sr_ethernet_hdr));
				return 6;
			}
		}

    // TODO: handle packets NOT addressed to this router. This will require 
    // routing them or dropping them based on the TTL. If a packet is dropped
    // due to TTL, send an ICMP TTL expired message. If a packet is to be
    // forwarded, fix its TTL and checksum here.
    
    /*if(!router_send_ethernet_frame(sr,hdr->ip_dst.s_addr,htons(ETHERTYPE_IP),
            packet,len))
    {
        Debug("Couldn't find a route to forward IP packet\n");
        
        // TODO: send an ICMP DESTINATION UNREACHABLE

        return 6;
    }*/
    return 0;

}

uint16_t checksum_ip( struct ip * hdr ) {
    hdr->ip_sum = 0;
    hdr->ip_sum = checksum( (uint16_t*)hdr, IPV4_HEADER_LEN );
    return hdr->ip_sum;
}



uint16_t checksum( uint16_t* buf, unsigned len ) {
    uint16_t answer;
    uint32_t sum;

    /* add all 16 bit pairs into the total */
    answer = sum = 0;
    while( len > 1 ) {
        sum += *buf++;
        len -= 2;
    }

    /* take care of the last lone uint8_t, if present */
    if( len == 1 ) {
        *(unsigned char *)(&answer) = *(unsigned char *)buf;
        sum += answer;
    }

    /* fold any carries back into the lower 16 bits */
    sum = (sum >> 16) + (sum & 0xFFFF);    /* add hi 16 to low 16 */
    sum += (sum >> 16);                    /* add carry           */
    answer = ~sum;                         /* truncate to 16 bits */

    return answer;
}

void icmp_send( struct sr_instance * router,
                uint32_t dst,
                uint32_t src,
                uint8_t* ip_packet, /* or just the data to send back */
                unsigned len,
                uint8_t type,
                uint8_t code,
                uint16_t extra1,
                uint16_t extra2 ) {

    // craft an ICMP packet with the given parameters, and call
    // network_send_packet(...,IP_PROTO_ICMP,...) to send it.

	//printf("In function icmp_send()\n");
	hdr_icmp_t * icmp_hdr;
	uint8_t * packet=(uint8_t *)malloc(ICMP_HEADER_LEN+len);
	icmp_hdr=(hdr_icmp_t *)packet;

	if(TIMEOUT)
	{
		icmp_hdr->type=ICMP_TYPE_TIME_EXCEEDED;
		icmp_hdr->code=ICMP_CODE_TTL_EXPIRED;
	}
	else if(UNREACH)
	{
		icmp_hdr->type=ICMP_TYPE_DEST_UNREACH;
		icmp_hdr->code=ICMP_CODE_HOST_UNREACH;
	}
	else
	{
		icmp_hdr->type=type;
		icmp_hdr->code=code;
	}
	icmp_hdr->short1=extra1;
	icmp_hdr->short2=extra2;

	memcpy(packet+ICMP_HEADER_LEN,ip_packet,len);
	checksum_icmp(icmp_hdr,ICMP_HEADER_LEN+len);

	network_send_packet(router,dst,IP_PROTO_ICMP,packet,ICMP_HEADER_LEN+len);


}

struct sr_if * router_lookup_interface_via_ip( struct sr_instance * sr, uint32_t dst )
{
    /* use rtable_find_route to find route, then look up sr_if based on route
     * interface's name
     */
    struct sr_rt * route = rtable_find_route(sr,dst);
	//printf("End look up\n");
    return sr_get_interface(sr,route->interface);

}



int network_send_packet( struct sr_instance * router,
                     uint32_t dst,
                     uint8_t proto_id,
                     uint8_t* payload,
                     unsigned len ) {
    struct sr_if * intf;
    uint32_t found_src;
    uint8_t * quad = (uint8_t*)&dst;
	//printf("in network_send_packet()\n");
    /* lookup the src address we'll send from to get to dst */
    // outgoing interface
    intf = router_lookup_interface_via_ip( router, dst );
    if( intf )
        // outgoing interface's IP
		//printf("Find a route\n");
        found_src = intf->ip;
        return network_send_packet_from( router, dst,found_src, proto_id, payload, len );

    /* couldn't route to dst */
    Debug( "Error: unable to find route in network_send_packet for %u.%u.%u.%u\n",quad[0],quad[1],quad[2],quad[3] );

    return FALSE;
}


// walk the list of interfaces and return true if dst == interface.ipaddr
int ip_to_me(struct sr_instance * sr, uint32_t dst)
{
    struct sr_if* if_walker = sr->if_list;
    while(if_walker)
    {
        if (if_walker->ip ==dst)
            return TRUE;
        if_walker = if_walker->next;
    }
    return FALSE;
}

void icmp_change_type(struct sr_instance * router,
                         uint8_t* ip_packet,
                         unsigned len ) {
    struct ip *  hdr_ip;
    hdr_icmp_t* hdr;
    unsigned headers_len;
    unsigned icmp_packet_len;
    uint16_t old_sum; 
            
    hdr = (hdr_icmp_t*)(ip_packet + IPV4_HEADER_LEN);
    icmp_packet_len = len - IPV4_HEADER_LEN;
            
	//printf("TYPE: %d\n ip %d\n icmp %d\n", hdr->type, ip_packet, hdr);
    if( hdr->type != ICMP_TYPE_ECHO_REQUEST ) {
        Debug( "%s only Echo Request and Reply is handled (received type %u)",
                       "ICMP packet dropped:",
                       hdr->type );
        return;
    }       

	if(TIMEOUT)
	{
		hdr->type=ICMP_TYPE_TIME_EXCEEDED;
		hdr->code=ICMP_CODE_TTL_EXPIRED;
	}
	else if(UNREACH)
	{
		hdr->type=ICMP_TYPE_DEST_UNREACH;
		hdr->code=ICMP_CODE_HOST_UNREACH;
	}
	else
	{
		hdr->type = ICMP_TYPE_ECHO_REPLY;
	}

	checksum_icmp(hdr, icmp_packet_len);
                       
	//printf("TYPE: %d\n ip %d\n icmp %d\n", hdr->type, ip_packet, hdr);
	return;
}
void icmp_handle_packet(struct sr_instance * router,
                         uint8_t* ip_packet,
                         unsigned len ) {
    struct ip *  hdr_ip;
    hdr_icmp_t* hdr;
    unsigned headers_len;
    unsigned icmp_packet_len;
    uint16_t old_sum; 
            
    hdr = (hdr_icmp_t*)(ip_packet + IPV4_HEADER_LEN);
    icmp_packet_len = len - IPV4_HEADER_LEN;
            
	//printf("TYPE: %d\n ip %d\n icmp %d\n", hdr->type, ip_packet, hdr);
    if( hdr->type != ICMP_TYPE_ECHO_REQUEST ) {
        Debug( "%s only Echo Request and Reply is handled (received type %u)",
                       "ICMP packet dropped:",
                       hdr->type );
        return;
    }       

                       
    old_sum = hdr->sum;
    if( old_sum != checksum_icmp(hdr, icmp_packet_len) ) {
        Debug( "%s checksum %u is incorrect:: should be %u",
                       "ICMP packet dropped:",
                       old_sum,
                       hdr->sum );
        return;
    }

    /* determine how much data came with the request */
    headers_len = IPV4_HEADER_LEN + ICMP_HEADER_LEN;

    /* send the reply to our sender from us (swapped dst/src fields) */
    hdr_ip = (struct ip*)ip_packet;
	if(TIMEOUT||UNREACH)
		icmp_send( router,
				hdr_ip->ip_src.s_addr, hdr_ip->ip_dst.s_addr,
				ip_packet,len,
				ICMP_TYPE_ECHO_REPLY, 0, hdr->short1, hdr->short2);
	else
		icmp_send( router,
				hdr_ip->ip_src.s_addr, hdr_ip->ip_dst.s_addr,
				ip_packet+headers_len, len - headers_len,
				ICMP_TYPE_ECHO_REPLY, 0, hdr->short1, hdr->short2 );
}

uint16_t checksum_icmp( hdr_icmp_t* icmp_hdr, unsigned total_len ) {
    icmp_hdr->sum = 0;
    icmp_hdr->sum = checksum( (uint16_t*)icmp_hdr, total_len );
    return icmp_hdr->sum;
}

int  network_send_packet_from( struct sr_instance* router,
                          uint32_t dst,
                          uint32_t src,
                          uint8_t proto_id,
                          uint8_t* buf,
                          unsigned len ) {
	//printf("In function network_send_packet_from()\n");
    int ret = 0;

	struct ip * ip_hdr;
    // TODO: allocate space for a network level packet and fill in the
    // appropriate fields and payload. use router_send_ethernet_frame
    // to send the packet on its way.
	
	uint8_t * packet;
	packet = (uint8_t *)malloc(IPV4_HEADER_LEN+len);

	ip_hdr = (struct ip*)packet;

	ip_hdr->ip_hl=5;
	ip_hdr->ip_v=4;
	ip_hdr->ip_len = htons(len+IPV4_HEADER_LEN);
	ip_hdr->ip_id=ipid;
	ip_hdr->ip_off=0;
	ip_hdr->ip_ttl=255;
	ip_hdr->ip_p=proto_id;
	ip_hdr->ip_tos=0;
	ip_hdr->ip_sum=0;
	ip_hdr->ip_src.s_addr = src;
	ip_hdr->ip_dst.s_addr = dst;

	memcpy(packet+IPV4_HEADER_LEN,buf,len);

	checksum_ip(ip_hdr);
	ret=router_send_ethernet_frame(router,dst,htons(ETHERTYPE_IP),packet,IPV4_HEADER_LEN+len);
    
    return ret;
}

// find outgoing interface based on routing table
struct sr_rt * rtable_find_route( struct sr_instance * sr,uint32_t dst_ip )
{
    // TODO: find the best route in your routing table for a given
    // IP address. The current implementation stores the available routes
    // unordered in the routing table, so you will have to iterate over
    // its linked list and find the best route. the first entry
    // in the routing table is stored at sr->routing_table.
	
	//printf("In function rtable_find_route()\n");

	
	struct sr_rt * ptr_rt = sr->routing_table;

	//printf("%d\n",dst_ip);

	if(TOME||REPING||TIMEOUT||UNREACH)
	{
		//printf("This is a packet to me\n");
		while(ptr_rt!=NULL)
		{
			if(strcmp(ptr_rt->interface,"eth0")==0)
			{
				//printf("Got eth0\n");
				break;
			}
			ptr_rt=ptr_rt->next;
		}
	}
	else
	{
		while(ptr_rt!=NULL)
		{
			//printf("%d\n",ntohl(ptr_rt->dest.s_addr));
			if(dst_ip==ptr_rt->dest.s_addr)
			{
				//printf("%s\n",inet_ntoa(ptr_rt->dest));
				break;
			}
			ptr_rt=ptr_rt->next;
		}
	}
	//printf("End rtable %s is found\n", ptr_rt->interface);

    return ptr_rt;
}

int router_send_ethernet_frame( struct sr_instance * router,
                                 uint32_t dst_ip,
                                 uint16_t type,
                                 uint8_t* payload,
                                 unsigned len ) {
    struct sr_rt * rti;
    struct sr_if * intf;
	//printf("In function router_send_ethernet_frame()\n");
    /* lookup which route to use */
    rti = rtable_find_route( router, dst_ip );
    if( !rti ) {
        Debug("no route for this IP\n");
        return FALSE; /* don't have a route for this IP */
    }
    intf = sr_get_interface(router,rti->interface);
	//printf("Interface: %s\n", rti->interface);
    router_queue_ethernet_frame(router, rti,intf, type, payload, len );
    return TRUE;
}

int router_queue_ethernet_frame(struct sr_instance * sr,
                                     struct sr_rt * rti,
                                     struct sr_if * intf,
                                     uint16_t type,
                                     uint8_t* payload,
                                     unsigned payload_len ) {


	//printf("*** -> IN FUNCTION router_queue_ethernet_frame\n");
    addr_mac_t dst;
    if(arp_table_get_entry(sr,rti->gw.s_addr,&dst))
    {
		//printf("Thi is %s\n",rti->interface);
		printf("*** -> An arp entry is found\n");
        // TODO:
        // at this point in the code, an ARP cache entry has been
        // found for the destination IP.  Send the packet immediately.


		unsigned int ether_hdr_len = sizeof(struct sr_ethernet_hdr);
		uint8_t * frame = (uint8_t *)malloc(ether_hdr_len+payload_len);
		struct sr_ethernet_hdr * ether_hdr = (struct sr_ethernet_hdr *)frame;

		ether_hdr->ether_type=type;
		memcpy(&(ether_hdr->ether_dhost),&dst,sizeof(addr_mac_t));
		memcpy(&(ether_hdr->ether_shost),&(intf->addr),sizeof(addr_mac_t));
		memcpy(frame+ether_hdr_len,payload,payload_len);

		sr_send_packet(sr,frame,ether_hdr_len+payload_len,intf->name);
        
        return TRUE;
    }
    
    // Else - queue_ethernet_wait_arp will send an ARP request
    // if necessary and send the packet once the dst MAC is found.
    queue_ethernet_wait_arp(sr,rti,intf,type,payload,payload_len);
   
    return FALSE;
}


