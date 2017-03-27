#include <iostream>
#include <iomanip>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iterator>
#include <algorithm>
#include <sstream>
#include "pcap_parser.h"

PcapParser::PcapParser(const char *path) {
	char errbuff[PCAP_ERRBUF_SIZE];		/* error string */

	/* open file for offline processing in microseconds precision */
	descr_ = pcap_open_offline_with_tstamp_precision(path, 
													 PCAP_TSTAMP_PRECISION_MICRO, 
													 errbuff);
	if (descr_ == nullptr)
		throw ParserException(errbuff);
}

PcapParser::~PcapParser(void) {
	/* close descriptor if opened */
	if (descr_)
		pcap_close(descr_);
}

void PcapParser::Process(void) const {
	struct bpf_program filter;			/* pcap filter */
	std::stringstream ss;  

    for (auto  it = filters_.begin(); it != filters_.end(); ++it) {
     	ss << "(" << (*it)->ConvertToPcapFormat() << ")";
 
    	if(it != filters_.end() - 1)
       		ss << " and ";
    }
	std::string tmp_str = ss.str();
	const char *filter_exp = tmp_str.c_str();

	if (pcap_compile(descr_, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0) 
		throw ParserException(pcap_geterr(descr_));
    
    if (pcap_setfilter(descr_, &filter) < 0) 
        throw ParserException(pcap_geterr(descr_));

	if (pcap_loop(descr_, 0, PcapParser::PacketHandler, nullptr) < 0)
		throw ParserException(pcap_geterr(descr_));
}

void PcapParser::SetFilters(const std::vector<Filter::Ptr>& filters) {
	filters_ = filters;
}

void PcapParser::RemoveAllFilters(void) {
	filters_.clear();
}

void PcapParser::PacketHandler(u_char *args, 
					   	       const struct pcap_pkthdr *header, 
					   		   const u_char *packet) {
	const struct ether_header *ethernet_header;		/* Ethernet frame header */
	const struct ip *ip_header;						/* IP packet header */
	const struct udphdr *udp_header;				/* UDP datagram header */
  	char dst_ip[INET_ADDRSTRLEN];					/* Destination IP-address */
  	u_int dst_port;									/* Destination port */
    short data_len;									/* Payload data size*/

  	ethernet_header = (struct ether_header*)packet;
  	/* Handle only IP packets */
	if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
		return;

	ip_header = (struct ip*)(packet + sizeof(ether_header));
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    /* Handle only UDP datagrams */
    if (ip_header->ip_p != IPPROTO_UDP)
    	return;

    udp_header = (udphdr*)(packet + sizeof(ether_header) + sizeof(ip));
    dst_port = ntohs(udp_header->uh_dport);
    data_len = ntohs(udp_header->uh_ulen) - sizeof(udphdr);

    PrintPacketInfo(&header->ts, dst_ip, dst_port, data_len);
}

void PcapParser::PrintPacketInfo(const struct timeval *ts,
								 const char *address,
								 const u_int port,
								 short payload_size) {
	/** 
	 * Convert timeval from seconds to readable format, e.g:
	 * 2017-03-20 18:11:02
	 */
	struct tm *packet_tm = localtime(&ts->tv_sec);
	char tmbuf[64];
	const char *format = "%Y-%m-%d %H:%M:%S";
	strftime(tmbuf, sizeof(tmbuf), format, packet_tm);

	std::cout << tmbuf << ".";
	std::cout << std::setfill('0') << std::setw(6) << ts->tv_usec << "\t";
	std::cout << std::left << std::setw(20) << std::setfill(' ') << address;
	std::cout << std::left << std::setw(10) << std::setfill(' ') << port;
	std::cout << std::left << std::setw(10) << std::setfill(' ') << payload_size << std::endl;
}