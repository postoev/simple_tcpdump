/*
* print_pcap - console application to extract 
* UDP/IP-datagrams from .pcap file 

* Functions:
* 1. Reject all not UDP/IP packets (e.g, TCP/IP)
* 2. Filter UDP-datagrams by IP-address or/and 
* destination port
* 3. Doesn't support IPv6
*
* Usage: print_pcap [OPTION]... [FILE]
* Mandatory argument: path to .pcap file
* Optional arguments:
* 	-a ADDRESS		print only UDP-datagrams, were sent to address [ADDRESS] 	    
* 	-p PORT			print only UDP-datagrams, were sent to port [PORT]
*
* Examples:
* 1. Print all UDP-datagrams from file:
*	./print_pcap dump.pcap

* 2. Print only UDP-datagrams, were sent to address 192.168.1.22:
*	./print_pcap -a 192.168.1.22 dump.pcap

* 3. Print only UDP-datagrams, were sent to address 192.168.1.22:9991:
*	./print_pcap -a 192.168.1.22 -p 9991 dump.pcap
*
* Output format:
* <Timestap (microseconds precision)> <Dst Address> <Dst Port> <Payload Size in UDP-datagram>
*/

#include <unistd.h>
#include <iostream>
#include "pcap_parser.h"

static const char *option_string = "a:p:";		/* possible program options */

void usage(const char* app_name) {
	std::cout << "Usage: " << app_name <<  " [-a <address>] [-p <port>] <path>" << std::endl;
	exit (EXIT_FAILURE);
}

int main(int argc, char **argv) {
	char arg = 0;
	std::vector<Filter::Ptr> filters;

	try {
		while ((arg = getopt(argc, argv, option_string)) != -1) {
			switch (arg) {
				case 'a':
					filters.emplace_back(new DstIpV4AddressFilter(optarg));
					break;
				case 'p':
					filters.emplace_back(new DstPortFilter(optarg));
					break;
				default:
					usage(argv[0]);
			}
		}
		if (argv[optind] == nullptr) {
			std::cerr << argv[0] << ": missing operand" << std::endl;
			usage(argv[0]);
		} 
		else if (argv[optind + 1] != nullptr) {
			std::cerr << argv[0] << ": too many arguments" << std::endl;
			usage(argv[0]);
		}

		auto parser = PcapParser::Ptr(new PcapParser(argv[optind]));
		parser->SetFilters(filters);
		parser->Process();	
	}
	catch (const ValidationException& e) {
		std::cerr << "Wrong input exception: " << e.what() << std::endl;
		usage(argv[0]);
	}
	catch (const ParserException& e) {
		std::cerr << "Error while parsing .pcap file: " << e.what() << std::endl;
		exit (EXIT_FAILURE);
	}
	catch (const std::exception& e) {
		std::cerr << "General error occured: " << e.what() << std::endl;
		exit (EXIT_FAILURE);
	}
	exit (EXIT_SUCCESS);	
}