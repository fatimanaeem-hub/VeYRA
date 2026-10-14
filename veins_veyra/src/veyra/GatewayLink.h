//
// VEYRA - link from an RSU inside OMNeT++ to gateway_service.py.
//
// One blocking TCP connection per RSU, one JSON object per line, request ->
// reply (see PROTOCOL.md). Works on Windows (Winsock) and Linux/macOS.
//
// The few JSON helpers below only read the flat fields the RSU needs from
// the service's replies; they are not a general JSON parser.
//

#pragma once

#include <string>

namespace veyra {

class GatewayLink {
public:
    GatewayLink() = default;
    ~GatewayLink();
    GatewayLink(const GatewayLink&) = delete;
    GatewayLink& operator=(const GatewayLink&) = delete;

    // Returns "" on success, otherwise a readable error.
    std::string connectTo(const std::string& host, int port);

    // Sends one JSON line and waits for the reply line. Throws std::runtime_error
    // if the connection breaks.
    std::string request(const std::string& jsonLine);

    bool isOpen() const
    {
        return fd >= 0;
    }
    void close();

private:
    long long fd = -1; // SOCKET on Windows, int elsewhere
    std::string pending; // bytes received after the last '\n'
};

// --- tiny JSON helpers ------------------------------------------------------
std::string jsonEscape(const std::string& s);

// Value of the first "key" in the text, as raw text (number, true/false/null,
// or a string without its quotes). Returns false if the key is missing.
bool jsonRaw(const std::string& json, const std::string& key, std::string& out);

std::string jsonString(const std::string& json, const std::string& key, const std::string& def = "");
double jsonNumber(const std::string& json, const std::string& key, double def = 0.0);
bool jsonBool(const std::string& json, const std::string& key, bool def = false);

// Number of times "key" appears (e.g. how many finalised transactions).
int jsonCount(const std::string& json, const std::string& key);

// Sum of every numeric "key" value (e.g. malicious readings over all
// finalised transactions).
double jsonSum(const std::string& json, const std::string& key);

} // namespace veyra
