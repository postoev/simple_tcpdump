#ifndef INPUT_VALIDATOR_H_
#define INPUT_VALIDATOR_H_

#include <arpa/inet.h>
#include <cstdlib>
#include <cctype>
#include <memory>
#include "exceptions.h"

/**
 * Interface for user's arguments validation
 */
class InputValidator {
public:
	using Ptr = std::shared_ptr<InputValidator>;

 	virtual ~InputValidator(void) { }

 	virtual void Validate(const char *input) const = 0;
};

/**
 * Check if input is valid IPv4 address string
 */
class IpV4Validator : public InputValidator {
public:
 	inline void Validate(const char *input) const override {
 		struct sockaddr_in sa;
		if (inet_pton(AF_INET, input, &sa.sin_addr) != 1)
			throw ValidationException("input wasn't recognized as valid IPv4 address");
 	}
};

/**
 * Check if input is valid port string
 */
class PortValidator : public InputValidator {
public:
 	inline void Validate(const char *input) const override {
 		auto port = strtol(input, nullptr, 0);
 		if ((port <= 0) || (port > 65535))
 			throw ValidationException("input wasn't recognized as port number");
 	}
 };

#endif