#include <stdio.h>
#include <stdlib.h>
#include <string.h>

  typedef unsigned int adress_type_t;
  typedef unsigned char uint8_t;
    typedef unsigned short uint16_t;
 typedef unsigned long uint32_t;	

const adress_type_t MAC = 1;
const adress_type_t IP  = 2;
const adress_type_t PORT  = 3;
  
unsigned char unsorted[] = {1,2,1};

struct eb_lm32_udp_link {
  /* Contents must fit in 12 bytes */
  uint8_t mac[6];
  uint8_t ipv4[4];
  uint8_t port[2];		
};



#define IP_START	0
#define IP_VER_IHL	0
#define IP_DSCP_ECN     (IP_VER_IHL+1)	
#define IP_TOL		(IP_DSCP_ECN+1)
#define IP_ID		(IP_TOL+2)
#define IP_FLG_FRG	(IP_ID+2)
#define IP_TTL		(IP_FLG_FRG+2)
#define IP_PROTO	(IP_TTL+1)
#define IP_CHKSUM	(IP_PROTO+1)
#define IP_SPA		(IP_CHKSUM+2)
#define IP_DPA		(IP_SPA+4)
#define IP_END		(IP_DPA+4)

#define UDP_START	IP_END	
#define UDP_SPP		IP_END
#define UDP_DPP     	(UDP_SPP+2)	
#define UDP_LEN		(UDP_DPP+2)
#define UDP_CHKSUM	(UDP_LEN+2)
#define UDP_END		(UDP_CHKSUM+2)

#define ETH_HDR_LEN	14
#define IP_HDR_LEN	IP_END-IP_START
#define UDP_HDR_LEN	UDP_END-UDP_START

const uint8_t myIP[] = {0xc0, 0xa8, 0x00, 0x65};
const uint8_t myPort[] = {0xeb, 0xd0};

const uint8_t* getIP(const uint8_t* myIP)
{
	return myIP;
}

uint16_t ipv4_checksum(uint8_t *buf, int shorts)
{
	int i;
	uint32_t sum;

	sum = 0;
	for (i = 0; i < shorts; i+=2)
		sum += (buf[i+0]<<8) | (buf[i+1]);
	
	//add carries to checksum
	sum = (sum >> 16) + (sum & 0xffff);
	//again in case this add had a carry	
	sum += (sum >> 16);
	//invert and truncate to 16 bit
	sum = (~sum & 0xffff);
	
	return (uint16_t)sum;
}

uint16_t udp_checksum(const uint8_t *hdrbuf, const uint8_t *databuf, uint16_t len)
{
	//Prep udp checksum	
	int i;
	uint32_t sum;

	sum = 0;

	//calc chksum for data 
	for (i = 0; i < (len & 0xfffe); ++i)
		sum += (databuf[i+0]<<8) | (databuf[i+1]);

	if(len & 0x01) 	sum += databuf[i];// if len is odd, pad the last byte and add
	
	//add pseudoheader
	sum += (hdrbuf[IP_SPA+0]<<8) | (hdrbuf[IP_SPA+1]);
	sum += (hdrbuf[IP_SPA+2]<<8) | (hdrbuf[IP_SPA+3]);
	sum += (hdrbuf[IP_DPA+0]<<8) | (hdrbuf[IP_DPA+1]);
	sum += (hdrbuf[IP_DPA+2]<<8) | (hdrbuf[IP_DPA+3]);
	sum += (uint16_t)hdrbuf[IP_PROTO];
	
	sum += (hdrbuf[UDP_SPP+0]<<8) | (hdrbuf[UDP_SPP+1]);
	sum += (hdrbuf[UDP_DPP+0]<<8) | (hdrbuf[UDP_DPP+1]);
	sum += (hdrbuf[UDP_LEN+0]<<8) | (hdrbuf[UDP_LEN+1]);
	sum += (hdrbuf[UDP_CHKSUM+0]<<8) | (hdrbuf[UDP_CHKSUM+1]);

	//add carries and return complement
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	sum = (~sum & 0xffff);
	return (uint16_t)sum;
}


uint8_t* createUdpIpHdr(struct eb_lm32_udp_link* linkp, uint8_t* hdrbuf, const uint8_t* databuf, uint16_t len)
{
	struct eb_lm32_udp_link* link;
  	link = (struct eb_lm32_udp_link*)linkp;
	uint16_t ipchksum, sum;
	uint16_t shorts;
	uint16_t iptol, udplen;
	
	

	iptol  = len + IP_HDR_LEN + UDP_HDR_LEN;
	udplen = len + UDP_HDR_LEN;

	// ------------- IP ------------
	hdrbuf[IP_VER_IHL]  	= 0x45;
	hdrbuf[IP_DSCP_ECN] 	= 0x00;
	hdrbuf[IP_TOL + 0]  	= (uint8_t)(iptol & 0xff); //length after payload
	hdrbuf[IP_TOL + 1]  	= (uint8_t)(iptol >> 8);
	hdrbuf[IP_ID + 0]  	= 0x00;
	hdrbuf[IP_ID + 1]  	= 0x00;
	hdrbuf[IP_FLG_FRG + 0]  = 0x00;
	hdrbuf[IP_FLG_FRG + 1]  = 0x00;	
	hdrbuf[IP_PROTO]	= 0x11; // UDP
	hdrbuf[IP_TTL]		= 0x01;
	
	memcpy(hdrbuf + IP_SPA, getIP(myIP),4); //source IP
	memcpy(hdrbuf + IP_DPA, link->ipv4, 4); //dest IP
	
	ipchksum = ipv4_checksum((&hdrbuf[0]), 10); //checksum
	
	hdrbuf[IP_CHKSUM + 0]  	= (uint8_t)(ipchksum >> 8);
	hdrbuf[IP_CHKSUM + 1]	= (uint8_t)(ipchksum);

	// ------------- UDP ------------
	
	memcpy(hdrbuf + UDP_SPP, myPort,2);
	memcpy(hdrbuf + UDP_DPP, link->port,2);
	hdrbuf[UDP_LEN + 0]  = (uint8_t)(udplen >> 8); //udp length after payload
	hdrbuf[UDP_LEN + 1]  = (uint8_t)(udplen);
	hdrbuf[UDP_CHKSUM + 0]  = 0x00;
	hdrbuf[UDP_CHKSUM + 1]  = 0x00;

	//udp chksum
	sum = udp_checksum(hdrbuf, databuf, len);

	hdrbuf[UDP_CHKSUM+0] = (uint8_t)(sum >> 8); 
	hdrbuf[UDP_CHKSUM+1] = (uint8_t)(sum);

	return hdrbuf;
}





int main () {

 int i,j;
struct eb_lm32_udp_link mylink = {
	  {0xd1, 0x5e, 0xa5, 0xed, 0xbe, 0xef},
	  {0xde, 0xad, 0xbe, 0xe1},
          {0xca, 0xfe}
	 };

uint8_t hdrbuf[32];
uint8_t databuf[8] = {0x12, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

createUdpIpHdr(&mylink, &hdrbuf[0], &databuf[0], 8);

printf("Header: ");
printf("\n");
    
for(j=0;j<7;j++)
{
for(i=0;i<4;i++) printf(" %02X", *(hdrbuf+(j*4+i)));
printf("\n");
}

printf("IP Chksum: %04X \n", ipv4_checksum(hdrbuf, 12)); 
printf("UDP Chksum %04X \n", udp_checksum(hdrbuf, databuf, 8));
    return 0;

}

