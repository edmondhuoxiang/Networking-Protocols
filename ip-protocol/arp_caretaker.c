void queue_ethernet_wait_arp(struct sr_instance * sr,
                                     struct sr_rt * rti,
                                     struct sr_if * intf,
                                     uint16_t type,
                                     uint8_t* payload,
                                     unsigned payload_len ) {
    // find space on the pq for this outgoing packet
    uint8_t * buf;
    unsigned len = ETH_HEADER_LEN + payload_len;
    buf = malloc(len);
    rmutex_lock(&sr->arp_queue_lock);

    /* set the from address field */
    memcpy( buf+ETHER_ADDR_LEN, &intf->addr, ETHER_ADDR_LEN );

    /* set the type and payload fields */
    memcpy( buf+ETHER_ADDR_LEN*2, &type, sizeof(type) );
    memcpy( buf+ETH_HEADER_LEN, payload, payload_len );

    for(int i = 0; i < OUTSTANDING_ARP_LIMIT ; i++)
    {
        // space exists to queue the packet
        if (sr->pq[i].payload == 0)
        {
            // ptr to lowest empty arptable entry
            struct arp_response_queue_entry * ae = NULL;
            // walk outstanding arp data structure to find room
            for( int j = 0; j < OUTSTANDING_ARP_LIMIT; j++)
            {
                if(sr->aq[j].ip == rti->gw.s_addr)
                {
                    time_t now = time(NULL);
                    Debug("arp request already queued for this IP\n");
                    // queue the packet and return
                    sr->pq[i].payload = buf;
                    sr->pq[i].expiry = now + PACKET_TIMEOUT;
                    sr->pq[i].ip = rti->gw.s_addr;
                    sr->pq[i].iface = intf->name;
                    sr->pq[i].payload_len = len;
                    rmutex_unlock(&sr->arp_queue_lock);
                    return;
                }
                else if (sr->aq[j].ip == 0)
                    ae = &sr->aq[j];
            }
            if (!ae)
            {
                Debug("pending arp request queue full, dropping packet\n");
                rmutex_unlock(&sr->arp_queue_lock);
                return;
            }
            // expiry 0 - arp sent next wakeup
            Debug("Queueing ARP packet to go out %s\n",intf->name);
            ae->expiry = 0;
            ae->req_remaining = ARP_ATTEMPTS;
            ae->ip = rti->gw.s_addr;
            ae->iface = intf->name;
            sr->pq[i].payload = buf;
            sr->pq[i].payload_len = len;
            sr->pq[i].expiry = time(NULL) + PACKET_TIMEOUT;
            sr->pq[i].ip = rti->gw.s_addr;
            sr->pq[i].iface = intf->name;
            rmutex_unlock(&sr->arp_queue_lock);
            return ;
        }
    }
    Debug("arp packet queue full, dropping packet\n");
    rmutex_unlock(&sr->arp_queue_lock);

}


int arp_table_set_entry(struct sr_instance * sr, uint32_t ip, addr_mac_t macaddr)
{
    int arp_LRU = -1;
    int cache_found = 0;
    int now = time(NULL);
    rmutex_lock(&sr->arptable_lock);
    for(int i = 0; i < ARP_TABLE_SIZE; i++)
    {
        // find space for this entry in the arp cache
        if (sr->arptable[i].ipaddr == ip || sr->arptable[i].expiry < now || sr->arptable[i].expiry == 0)
        {
            sr->arptable[i].ipaddr = ip;
            sr->arptable[i].expiry = now + ARP_CACHE_RESIDENCY_TIME;
            memcpy(&sr->arptable[i].ethaddr,&macaddr,ETHER_ADDR_LEN);
            cache_found = 1;
            break;
        }
        // in the case that we don't find an empty/stale
        // arp cache entry, find least recently used and eject that one.
        if( arp_LRU < 0 || sr->arptable[i].expiry < sr->arptable[arp_LRU].expiry)
            arp_LRU = i;
    }
    if (!cache_found)
    {
        sr->arptable[arp_LRU].ipaddr = ip;
        // default arp cache residency time is 20 minutes
        sr->arptable[arp_LRU].expiry = now + 60*20;
        memcpy(&sr->arptable[arp_LRU].ethaddr,&macaddr,ETHER_ADDR_LEN);
    }
    rmutex_unlock(&sr->arptable_lock);
    //TODO optional: signal the pending packet queue to check to see if
    //it got info it needed to send a packet
    return TRUE;
}

int arp_table_get_entry(struct sr_instance * sr, uint32_t ip, addr_mac_t * addr){
    rmutex_lock(&sr->arptable_lock);
    time_t now = time(NULL);
    for(int i = 0; i < ARP_TABLE_SIZE; i++)
    {
        if (sr->arptable[i].ipaddr == ip && sr->arptable[i].expiry > now)
        {
            *addr = sr->arptable[i].ethaddr;
            rmutex_unlock(&sr->arptable_lock);
            return TRUE;
        }
    }
    rmutex_unlock(&sr->arptable_lock);
    return FALSE;
}

void *  arp_queue_caretaker(void * router){
    struct sr_instance * sr = router;
    while(TRUE)
    {
        // walk the packet queue, send and clear any that are sendable
        rmutex_lock(&sr->arp_queue_lock);
        for(int i = 0; i < OUTSTANDING_ARP_LIMIT; i++)
        {
            if (sr->pq[i].payload)
            {
                addr_mac_t result;
                if (arp_table_get_entry(sr,sr->pq[i].ip,&result))
                {
                    Debug("found destination in arp cache, sending packet\n");
                    memcpy(sr->pq[i].payload,&result,ETHER_ADDR_LEN);
                    sr_send_packet(sr,sr->pq[i].payload,sr->pq[i].payload_len,sr->pq[i].iface);
                    free(sr->pq[i].payload);
                    sr->pq[i].payload = NULL;
                    continue;
                }
                // last chance failed, drop this packet
                else if (sr->pq[i].expiry < time(NULL))
                {
                    // grab the pointer so we can send the icmp error,
                    // but free up the outgoing IP packet cache entry
                    uint8_t * buf = sr->pq[i].payload;
                    sr->pq[i].payload = NULL;
                    Debug("sending icmp host unreach on arp timeout\n");
                    // send ICMP HOST UNREACH back to sender to inform
                    // them that we cannot route this packet
                    
                    uint32_t dst = ((struct ip *)(buf + sizeof(struct sr_ethernet_hdr)))->ip_src.s_addr;
                    icmp_send(sr,dst,0,buf + sizeof(struct sr_ethernet_hdr),sr->pq[i].payload_len - sizeof(struct sr_ethernet_hdr),ICMP_TYPE_DEST_UNREACH,ICMP_CODE_HOST_UNREACH,0,0);
                    free(buf);
                }
            }
        }
        // walk the pending arp request queue, sending or deleting entries
        // as necessary
        for(int i = 0; i < OUTSTANDING_ARP_LIMIT; i++)
        {
            // clear entries that responses have been found for
            addr_mac_t ret;
            if (sr->aq[i].ip && arp_table_get_entry(sr,sr->aq[i].ip,&ret))
            {
                sr->aq[i].ip = 0;
                continue;
            }
            if (sr->aq[i].ip != 0 && sr->aq[i].expiry < time(NULL))
            {
                if(sr->aq[i].req_remaining-- < 1) 
                {
                    // done trying this one, fail
                    sr->aq[i].ip = 0;
                    continue;
                }
                // reset the time remaining
                sr->aq[i].expiry = time(NULL) + ARP_TIMEOUT;
                // send an ARP request for this packet
                int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
                uint8_t * buf = malloc(len);
                memset(buf,0,len);
                Debug("crafting arp packet from %s\n",sr->aq[i].iface); 
                addr_mac_t saddr = sr_get_interface(sr,sr->aq[i].iface)->addr;
                uint32_t src_ip = sr_get_interface(sr,sr->aq[i].iface)->ip;
                struct sr_ethernet_hdr * eh = (struct sr_ethernet_hdr *)buf;
                struct sr_arphdr *  ah = (struct sr_arphdr *) (buf + sizeof(struct sr_ethernet_hdr));
                // set ethernet fields
                eh->ether_shost = saddr;
                memset(&eh->ether_dhost,0xFF,ETHER_ADDR_LEN);
                eh->ether_type = htons(ETHERTYPE_ARP);
                // set arp fields
                ah->ar_hrd = htons(ARPHDR_ETHER);
                ah->ar_pro = htons(ETHERTYPE_IP);
                ah->ar_hln = 6;
                ah->ar_pln = 4;
                ah->ar_op = htons(ARP_REQUEST);
                ah->ar_sha = saddr;
                ah->ar_sip = src_ip;
                ah->ar_tip = sr->aq[i].ip;
                memset(&ah->ar_tha,0,ETHER_ADDR_LEN);
                Debug("sr_send_packet sending arp request out interface %s with length %d\n",sr->aq[i].iface,len);
                sr_send_packet(sr,buf,len,sr->aq[i].iface);
                free(buf);
            }
        }
        rmutex_unlock(&sr->arp_queue_lock);
        sleep(1);
    }
    return NULL;
}
