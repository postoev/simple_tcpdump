#ifndef PCAP_PARSER_H_
#define PCAP_PARSER_H_

/*
 * Parser object, is responsible for:
 * 	1. Reading and validating .pcap file 
 *	2. Rejecting useless packets, according to the filters 
 */

#include <vector>
#include <pcap/pcap.h>
#include "filter.h"

class PcapParser {
public:
	using Ptr = std::unique_ptr<PcapParser>;

	explicit PcapParser(const char *path);
	~PcapParser(void);
	
	// disable copy-assignment operators
	PcapParser(const PcapParser&) = delete;
	PcapParser& operator=(const PcapParser&) = delete;

	/* 
	 * Parse .pcap file and display only useful data
	 */
	void Process(void) const;
	/* 
	 * Set packet filters (to apply filter, call Process() again)
	 */
	void SetFilters(const std::vector<Filter::Ptr>& filter);
	/* 
	 * Remove all filters (all packets will be displayed 
	 * after calling Process() again)
	 */
	void RemoveAllFilters(void);

private:
	/* 
	 * Callback function, to handle intercepted traffic
	 */
	static void PacketHandler(u_char *args, 
					   		  const struct pcap_pkthdr *header, 
					   		  const u_char *packet);

	/* 
	 * Print packet content in format:
	 * <Timestap (microseconds precision)> <Dst Address> <Dst Port> <Payload Size>
	 */
	static void PrintPacketInfo(const struct timeval *ts,
								const char *address,
								const u_int port,
								short payload_size);

	pcap_t *descr_;						/* pcap file descriptor */
	std::vector<Filter::Ptr> filters_;	/* output filters */
};

#endif 
