#ifndef FILTER_H_
#define FILTER_H_

#include "input_validator.h"

/**
 * Abstact base class for packet filters
 */
class Filter {
public:
	/** 
	 * If no validator is set for filter, just do nothing 
	 * if input is mailformed, will throw ValidationException  
	 */ 
	using Ptr = std::shared_ptr<Filter>;

	Filter(const char *filter_param,
		   InputValidator::Ptr validator) {
		if (validator != nullptr) 
			validator->Validate(filter_param);
	}
	virtual ~Filter(void) { }

	/** 
	 * Interface function, convert filter params
	 * from standard input to pcap format 
	 */
	virtual std::string ConvertToPcapFormat() const = 0; 	
};

/**
 * Class for packet's filters based on destination address 
 * (IPv4 support only!)
 */
 class DstIpV4AddressFilter : public Filter {
 public:
 	explicit DstIpV4AddressFilter(const char *filter_param, 
 								  InputValidator::Ptr validator = InputValidator::Ptr(new IpV4Validator()));

	std::string ConvertToPcapFormat(void) const override;

private:
	std::string dst_address_;
 };

 /**
 * Class for packet's filters based on destination port 
 */
 class DstPortFilter : public Filter {
 public:
 	explicit DstPortFilter(const char *filter_param, 
 						   InputValidator::Ptr validator = InputValidator::Ptr(new PortValidator()));

	std::string ConvertToPcapFormat(void) const override;

private:
	std::string dst_port_;
 };


#endif
