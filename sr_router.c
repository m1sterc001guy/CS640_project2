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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */
      printf("SEND ICMP host unreachable!!\n");



      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
      printf("SEND ALL PACKETS ON THE req->packets linked list\n");
      struct sr_packet *curr_packet = req->packets; 
      sr_ethernet_hdr_t *arp_hdr = (sr_ethernet_hdr_t *)(pkt);
      printf("ARP PACKET: \n");
      print_hdrs(pkt, len);
      while(curr_packet != NULL){
         sr_ethernet_hdr_t *curr_ether = (sr_ethernet_hdr_t *)(curr_packet->buf);
         memcpy(curr_ether->ether_shost, arp_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
         memcpy(curr_ether->ether_dhost, arp_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
         printf("PACKET TO SEND\n");
         print_hdrs(curr_packet->buf, curr_packet->len);
         printf("Interface: %s\n", curr_packet->iface);
         sr_send_packet(sr, curr_packet->buf, curr_packet->len, curr_packet->iface);
         curr_packet = curr_packet->next;
      }


      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

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
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*our first job is to get the correct Ethertype from the ethernet header to figure out what to do with the packet*/
  uint16_t ethtype = ethertype(packet);
  if(ethtype == ethertype_arp){
     printf("This is an ARP Packet!\n");
     print_hdrs(packet, len);
     /*our next job is to retreive the ARP header of the packet so we can figure out which host this packet is trying to resolve*/
     /*this might not be necessary because we might only handle arp requests to the router, not to every host*/
     struct sr_rt *curr_entry = sr->routing_table;
     while(curr_entry != NULL){
        curr_entry = curr_entry->next;  
     }
     sr_handlepacket_arp(sr, packet, len, sr_get_interface(sr, interface));
     /*print_addr_ip_int(htonl(ip));*/
  }
  else if(ethtype == ethertype_ip){
     printf("This is an IP Packet!\n");
     print_hdrs(packet, len);
     /*first we must check if the ip packet is destined for one of the routers interfaces*/
     /*get the destination ip address from the ip header*/
     sr_ip_hdr_t *destination = (sr_ip_hdr_t *)(packet + (sizeof(sr_ethernet_hdr_t)));
     struct sr_if *curr_entry = sr->if_list;
     int found = 0;
     while(curr_entry != NULL){
        /*compare the destination ip address with our interfaces to see if this ip packet is supposed to go to one of our interfaces*/
        if(curr_entry->ip == destination->ip_dst){
           found = 1;
           printf("FOUND! This packet is destined for one of the routers interfaces");
           /*TODO ADD logic for what happens when a packet comes to one of our interfaces*/
        }
        curr_entry = curr_entry->next;
     }
     if(!found){
        int min_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        if(len < min_length){
           fprintf(stderr, "This IP packet is not long enough!\n");
           return;
        }
        /*check the checksum on this packet*/
        /*int ip_header_length = sizeof(sr_ip_hdr_t);
        uint16_t check_sum = cksum(destination, ip_header_length); 
        if(check_sum != 0xffff){
           fprintf(stderr, "Incorrect checksum. Dropping packet...\n");
           return;
        }
        */
        destination->ip_ttl--;
        /*recompute the checksum for this packet*/
        /*destination->ip_sum = cksum(destination, ip_header_length);*/

        uint32_t ip_dest = destination->ip_dst;
        char *iface_to_send;
        uint32_t ip_to_send;
        int max_matching_bits = 0;
        int CHAR_BIT = 8; /*number of bits in a byte*/
        struct sr_rt *curr_entry = sr->routing_table; 
        while(curr_entry != NULL){
          uint32_t curr_ip = htonl(*(uint32_t *)&curr_entry->dest); 
          int matching_bits = 0;
          int i;
          for(i = sizeof(ip_dest) * (CHAR_BIT-1); i >= 0; --i){
              int ip_dest_bit = (ip_dest >> i) & 1;
              int curr_entry_bit = (curr_ip >> i) & 1;
              if(ip_dest_bit == curr_entry_bit){
                 matching_bits++;
              }
              else{
                 break;
              }
          }
          if(matching_bits > max_matching_bits){
             max_matching_bits = matching_bits;
             iface_to_send = curr_entry->interface;
             ip_to_send = curr_ip;
          }
          curr_entry = curr_entry->next;
        }
        printf("Interface to send: %s\n", iface_to_send);
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_to_send);
        if(arp_entry != NULL){
           printf("IP -> ARP CACHE HIT\n");
           /*send the packet to the next hop MAC address*/
        }
        else{
           printf("IP -> ARP CACHE MISS\n");
           printf("ip_to_send: \n");
           print_addr_ip_int(ip_to_send);
           printf("Interface: %s\n", iface_to_send);
           sr_waitforarp(sr, packet, len, ntohl(ip_to_send), sr_get_interface(sr, iface_to_send)); 
        }
     }
  }
  else{
     printf("This packet type did not match any currently known packet types!\n");
  }

  /*
  printf("ROUTING TABLE: \n");
  sr_print_routing_table(sr);
  printf("HEADERS: \n");
  print_hdrs(packet, len);
  */

  /*************************************************************************/
  /* TODO: Handle packets                                                  */



  /*************************************************************************/

}/* end sr_ForwardPacket */

