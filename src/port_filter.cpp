#include "filter.h"

DstPortFilter::DstPortFilter(const char *filter_param, 
 					   		 InputValidator::Ptr validator)
	: Filter(filter_param, validator), dst_port_(filter_param) { }

std::string DstPortFilter::ConvertToPcapFormat(void) const {
	return "dst port " + dst_port_;
}