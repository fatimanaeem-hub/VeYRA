//
// VEYRA - link from an RSU inside OMNeT++ to gateway_service.py.
//

#include "veyra/GatewayLink.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define VEYRA_CLOSE closesocket
#define VEYRA_INVALID(s) ((s) == INVALID_SOCKET)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#define VEYRA_CLOSE ::close
#define VEYRA_INVALID(s) ((s) < 0)
#endif

namespace veyra {

namespace {

const int kReplyTimeoutSeconds = 60;

#ifdef _WIN32
bool winsockReady()
{
    static bool done = false;
    static bool ok = false;
    if (!done) {
        WSADATA wsa;
        ok = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
        done = true;
    }
    return ok;
}
#endif

} // namespace

GatewayLink::~GatewayLink()
{
    close();
}

void GatewayLink::close()
{
    if (fd >= 0) {
#ifdef _WIN32
        VEYRA_CLOSE(static_cast<SOCKET>(fd));
#else
        VEYRA_CLOSE(static_cast<int>(fd));
#endif
    }
    fd = -1;
    pending.clear();
}

std::string GatewayLink::connectTo(const std::string& host, int port)
{
    close();
#ifdef _WIN32
    if (!winsockReady()) return "WSAStartup failed";
#endif
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        return "cannot resolve " + host;
    }

#ifdef _WIN32
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#else
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#endif
    if (VEYRA_INVALID(s)) {
        freeaddrinfo(res);
        return "cannot create socket";
    }
    if (::connect(s, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) != 0) {
        freeaddrinfo(res);
        VEYRA_CLOSE(s);
        return "connection refused on " + host + ":" + portStr;
    }
    freeaddrinfo(res);

    // Small request/reply messages: switch off Nagle, otherwise each request
    // can wait ~40 ms for a delayed ACK and the run becomes very slow.
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));

    // Never wait forever for a reply. On Windows, clicking into the gateway
    // service's console window can pause it (QuickEdit); then OMNeT++ would
    // hang silently instead of reporting it.
#ifdef _WIN32
    DWORD timeoutMs = kReplyTimeoutSeconds * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
#else
    struct timeval tv;
    tv.tv_sec = kReplyTimeoutSeconds;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    fd = static_cast<long long>(s);
    return "";
}

std::string GatewayLink::request(const std::string& jsonLine)
{
    if (fd < 0) throw std::runtime_error("gateway link is not connected");
#ifdef _WIN32
    SOCKET s = static_cast<SOCKET>(fd);
#else
    int s = static_cast<int>(fd);
#endif
    std::string out = jsonLine;
    if (out.empty() || out.back() != '\n') out += '\n';

    size_t sent = 0;
    while (sent < out.size()) {
        int n = ::send(s, out.data() + sent, static_cast<int>(out.size() - sent), 0);
        if (n <= 0) throw std::runtime_error("gateway service closed the connection (send)");
        sent += static_cast<size_t>(n);
    }

    char buf[8192];
    for (;;) {
        size_t nl = pending.find('\n');
        if (nl != std::string::npos) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            return line;
        }
        int n = ::recv(s, buf, sizeof(buf), 0);
        if (n < 0) {
            throw std::runtime_error("no reply from the gateway service for " + std::to_string(kReplyTimeoutSeconds) +
                                     " s (if its window shows 'Select', press Esc in it)");
        }
        if (n == 0) throw std::runtime_error("gateway service closed the connection");
        pending.append(buf, static_cast<size_t>(n));
    }
}

// --- JSON helpers -------------------------------------------------------------

std::string jsonEscape(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char tmp[8];
                std::snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                o += tmp;
            }
            else {
                o += c;
            }
        }
    }
    return o;
}

static size_t findKey(const std::string& json, const std::string& key, size_t from)
{
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat, from);
    while (p != std::string::npos) {
        size_t q = p + pat.size();
        while (q < json.size() && (json[q] == ' ' || json[q] == '\t')) q++;
        if (q < json.size() && json[q] == ':') {
            q++;
            while (q < json.size() && (json[q] == ' ' || json[q] == '\t')) q++;
            return q; // start of the value
        }
        p = json.find(pat, p + 1);
    }
    return std::string::npos;
}

static bool readValueAt(const std::string& json, size_t q, std::string& out)
{
    if (q >= json.size()) return false;
    if (json[q] == '"') {
        std::string v;
        for (size_t i = q + 1; i < json.size(); i++) {
            char c = json[i];
            if (c == '\\' && i + 1 < json.size()) {
                char n = json[++i];
                switch (n) {
                case 'n': v += '\n'; break;
                case 't': v += '\t'; break;
                case 'r': v += '\r'; break;
                default: v += n;
                }
                continue;
            }
            if (c == '"') {
                out = v;
                return true;
            }
            v += c;
        }
        return false;
    }
    size_t e = q;
    while (e < json.size() && json[e] != ',' && json[e] != '}' && json[e] != ']' && json[e] != ' ') e++;
    out = json.substr(q, e - q);
    return true;
}

bool jsonRaw(const std::string& json, const std::string& key, std::string& out)
{
    size_t q = findKey(json, key, 0);
    if (q == std::string::npos) return false;
    return readValueAt(json, q, out);
}

std::string jsonString(const std::string& json, const std::string& key, const std::string& def)
{
    std::string v;
    if (!jsonRaw(json, key, v) || v == "null") return def;
    return v;
}

double jsonNumber(const std::string& json, const std::string& key, double def)
{
    std::string v;
    if (!jsonRaw(json, key, v) || v.empty() || v == "null") return def;
    char* end = nullptr;
    double d = std::strtod(v.c_str(), &end);
    return (end == v.c_str()) ? def : d;
}

bool jsonBool(const std::string& json, const std::string& key, bool def)
{
    std::string v;
    if (!jsonRaw(json, key, v)) return def;
    if (v == "true") return true;
    if (v == "false") return false;
    return def;
}

int jsonCount(const std::string& json, const std::string& key)
{
    int n = 0;
    size_t q = findKey(json, key, 0);
    while (q != std::string::npos) {
        n++;
        q = findKey(json, key, q);
    }
    return n;
}

double jsonSum(const std::string& json, const std::string& key)
{
    double sum = 0;
    size_t q = findKey(json, key, 0);
    while (q != std::string::npos) {
        std::string v;
        if (readValueAt(json, q, v)) sum += std::strtod(v.c_str(), nullptr);
        q = findKey(json, key, q);
    }
    return sum;
}

} // namespace veyra
