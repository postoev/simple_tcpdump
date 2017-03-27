#ifndef EXCEPTIONS_H_
#define EXCEPTIONS_H_

#include <exception>

/**
 * Error while parsing .pcap file
 */
class ParserException : public std::exception {
public:
	ParserException(const std::string& error_message)
		: error_message_(error_message) { }

	virtual const char* what() const noexcept {
		return error_message_.c_str();
	}

private:
	std::string error_message_;
};

/**
 * Error while validating user input
 */
class ValidationException : public std::exception {
public:
	ValidationException(const std::string& error_message)
		: error_message_(error_message) { }

	virtual const char* what() const noexcept {
		return error_message_.c_str();
	}
	
private:
	std::string error_message_;
};

#endif
