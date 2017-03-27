#include "filter.h"

DstIpV4AddressFilter::DstIpV4AddressFilter(const char *filter_param, 
 								  		   InputValidator::Ptr validator)
	: Filter(filter_param, validator), dst_address_(filter_param) { }

std::string DstIpV4AddressFilter::ConvertToPcapFormat(void) const {
	return "dst host " + dst_address_;
}