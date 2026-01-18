#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

/*
DNS Header Structure (12 bytes):
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID                       |  16 bits - copied from query
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |  16 bits - flags
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    QDCOUNT                    |  16 bits - question count
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ANCOUNT                    |  16 bits - answer count
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    NSCOUNT                    |  16 bits - authority count
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ARCOUNT                    |  16 bits - additional count
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    void parse_from(const char* buffer) {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer);
        id = (data[0] << 8) | data[1];
        flags = (data[2] << 8) | data[3];
        qdcount = (data[4] << 8) | data[5];
        ancount = (data[6] << 8) | data[7];
        nscount = (data[8] << 8) | data[9];
        arcount = (data[10] << 8) | data[11];
    }

    void write_to(char* buffer) const {
        uint8_t* data = reinterpret_cast<uint8_t*>(buffer);
        data[0] = (id >> 8) & 0xFF;
        data[1] = id & 0xFF;
        data[2] = (flags >> 8) & 0xFF;
        data[3] = flags & 0xFF;
        data[4] = (qdcount >> 8) & 0xFF;
        data[5] = qdcount & 0xFF;
        data[6] = (ancount >> 8) & 0xFF;
        data[7] = ancount & 0xFF;
        data[8] = (nscount >> 8) & 0xFF;
        data[9] = nscount & 0xFF;
        data[10] = (arcount >> 8) & 0xFF;
        data[11] = arcount & 0xFF;
    }

    static DNSHeader create_response(const DNSHeader& query) {
        DNSHeader response;
        response.id = query.id;

        // extract OPCODE
        uint16_t opcode = (query.flags >> 11) & 0x0F;
        uint16_t rd = (query.flags >> 8) & 0x01;

        uint16_t rcode = opcode == 0 ? 0 : 4;

        // build response flags
        // QR=1 (response)
        // OPCODE copied
        // AA=0
        // TC=0
        // RD copied
        // RA=0
        // Z=0
        // RCODE=0
        response.flags = (1 << 15) | (opcode << 11) | (rd << 8) | rcode;

        response.qdcount = query.qdcount;
        response.ancount = 0;
        response.nscount = 0;
        response.arcount = 0;

        return response;
    }
};

class DNSCompressionTable {
   private:
    std::map<std::string, size_t> offsets;

   public:
    /**
     * Record a name and all its suffixes at the given offset
     * e.g. "www.google.com" at offset 12 records:
     *   - "www.google.com" -> 12
     *   - "google.com" -> 16
     *   - "com" -> 24
     */
    void record_name(const std::string& name, size_t offset) {
        std::string suffix = name;
        size_t pos = 0;
        while (!suffix.empty()) {
            if (offsets.find(suffix) == offsets.end()) {
                offsets[suffix] = offset + pos;
            }
            size_t dot = suffix.find('.');
            if (dot == std::string::npos) {
                break;
            }
            pos += dot + 2;  // +1 for label length byte; +1 to skip dot
            suffix = suffix.substr(dot + 1);
        }
    }

    std::pair<size_t, size_t> find_pointer(const std::string& name) const {
        std::string suffix = name;
        size_t name_pos = 0;
        while (!suffix.empty()) {
            auto it = offsets.find(suffix);
            if (it != offsets.end() && it->second < 0x3FFF) {
                // 14-bit max
                return {name_pos, it->second};
            }
            size_t dot = suffix.find('.');
            if (dot == std::string::npos) break;
            name_pos = name_pos + dot + 1;
            suffix = suffix.substr(dot + 1);
        }

        return {std::string::npos, 0};
    }
};

/**
 * Helper function to parse a domain name, handling compression pointers
 * Parameters:
 *   - `msg_start`: pointer to beginning of the entire DNS message
 *   - `current_pos`: pointer to where the domain name starts in the buffer
 * Returns: {parsed_name, bytes_consumed_at_current_position}
 */
std::pair<std::string, size_t> parse_domain_name(const char* msg_start,
                                                 const char* current_pos) {
    const uint8_t* msg = reinterpret_cast<const uint8_t*>(msg_start);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(current_pos);
    std::string name;
    size_t offset = 0;
    size_t bytes_consumed = 0;
    bool jumped = false;  // whether we've followed a compression pointer

    while (true) {
        // first byte is length of the domain name, e.g. for example.com
        // [7]example[3]com[0]
        uint8_t len = data[offset];
        if (len == 0) {
            // end of name
            if (!jumped) {
                bytes_consumed = offset + 1;
            }
            break;
        }

        // detects if the top 2 bits are `11`
        if ((len & 0xC0) == 0xC0) {
            // compression pointer: 2 bytes, upper 2 bits are `11`
            if (!jumped) {
                bytes_consumed = offset + 2;  // only count first pointer
            }

            // extract the 14-bit offset
            uint16_t ptr = ((len & 0x3F) << 8) | data[offset + 1];
            data = msg + ptr;  // jump to pointed location
            offset = 0;        // reset offset to zero since we've jumped
            // if jumped, we are reading from elsewhere in the message,
            // so we stop updating `bytes_consumed`
            jumped = true;
            continue;
        }

        // regular label
        if (!name.empty()) {
            name += '.';
        }
        name.append(reinterpret_cast<const char*>(data + offset + 1), len);
        offset += len + 1;
    }

    return {name, bytes_consumed};
}

struct DNSQuestion {
    std::string qname;  // domain name (e.g., "google.com")
    uint16_t qtype;     // query type (1 = A record)
    uint16_t qclass;    // query class (1 = INTERNET)

    // return number of bytes consumed from buffer
    size_t parse_from(const char* msg_start, const char* current_pos) {
        auto [name, name_bytes] = parse_domain_name(msg_start, current_pos);
        qname = name;
        const uint8_t* data = reinterpret_cast<const uint8_t*>(current_pos);
        size_t offset = name_bytes;

        // parse QTYPE and QCLASS (big-endian)
        qtype = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        qclass = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        return offset;
    }

    // return number of bytes written
    size_t write_compressed_to(char* buffer, size_t msg_offset,
                               DNSCompressionTable& table) const {
        uint8_t* data = reinterpret_cast<uint8_t*>(buffer);
        size_t offset = 0;

        auto [suffix_pos, ptr_offset] = table.find_pointer(qname);

        if (suffix_pos == 0) {
            // entire name can be compressed
            data[offset++] = 0xC0 | ((ptr_offset >> 8) & 0x3F);
            data[offset++] = ptr_offset & 0xFF;
        } else {
            // record this name's position
            table.record_name(qname, msg_offset);

            // write QANME as labels
            size_t pos = 0;
            while (pos < qname.size()) {
                size_t dot_pos = qname.find('.', pos);
                if (dot_pos == std::string::npos) {
                    dot_pos = qname.size();  // end of qname?
                }
                uint8_t label_len = dot_pos - pos;
                data[offset++] = label_len;
                for (size_t i = pos; i < dot_pos; ++i) {
                    data[offset++] = qname[i];
                }
                pos = dot_pos + 1;
            }
            data[offset++] = 0;  // null terminator
        }

        // write QTYPE and QCLASS
        data[offset++] = (qtype >> 8) & 0xFF;
        data[offset++] = qtype & 0xFF;
        data[offset++] = (qclass >> 8) & 0xFF;
        data[offset++] = qclass & 0xFF;

        return offset;
    }

    size_t write_to(char* buffer) const {
        uint8_t* data = reinterpret_cast<uint8_t*>(buffer);
        size_t offset = 0;

        // write QANME as labels
        size_t pos = 0;
        while (pos < qname.size()) {
            size_t dot_pos = qname.find('.', pos);
            if (dot_pos == std::string::npos) {
                dot_pos = qname.size();  // end of qname?
            }
            uint8_t label_len = dot_pos - pos;
            data[offset++] = label_len;
            for (size_t i = pos; i < dot_pos; ++i) {
                data[offset++] = qname[i];
            }
            pos = dot_pos + 1;
        }
        data[offset++] = 0;  // null terminator

        // write QTYPE and QCLASS
        data[offset++] = (qtype >> 8) & 0xFF;
        data[offset++] = qtype & 0xFF;
        data[offset++] = (qclass >> 8) & 0xFF;
        data[offset++] = qclass & 0xFF;

        return offset;
    }
};

struct DNSAnswer {
    std::string name;            // domain name
    uint16_t type;               // record type (1 = A)
    uint16_t cl;                 // class (1 = IN)
    uint32_t ttl;                // time to live
    uint16_t rdlen;              // length of rdata
    std::vector<uint8_t> rdata;  // record data (IPv4 for A record)

    size_t write_to(char* buffer) const {
        uint8_t* data = reinterpret_cast<uint8_t*>(buffer);
        size_t offset = 0;

        // write full domain name as labels
        size_t pos = 0;
        while (pos < name.size()) {
            size_t dot_pos = name.find('.', pos);
            if (dot_pos == std::string::npos) {
                dot_pos = name.size();
            }
            uint8_t label_len = dot_pos - pos;
            data[offset++] = label_len;
            for (size_t i = pos; i < dot_pos; ++i) {
                data[offset++] = name[i];
            }
            pos = dot_pos + 1;
        }
        data[offset++] = 0;  // null terminator

        // TYPE
        data[offset++] = (type >> 8) & 0xFF;
        data[offset++] = type & 0xFF;
        // CLASS
        data[offset++] = (cl >> 8) & 0xFF;
        data[offset++] = cl & 0xFF;

        // TTL (big-endian, 4 bytes)
        data[offset++] = (ttl >> 24) & 0xFF;
        data[offset++] = (ttl >> 16) & 0xFF;
        data[offset++] = (ttl >> 8) & 0xFF;
        data[offset++] = ttl & 0xFF;

        // RDLENGTH
        data[offset++] = (rdlen >> 8) & 0xFF;
        data[offset++] = rdlen & 0xFF;

        // RDATA
        for (auto byte : rdata) {
            data[offset++] = byte;
        }

        return offset;
    }

    // return number of bytes written
    size_t write_compressed_to(char* buffer, size_t msg_offset,
                               DNSCompressionTable& table) const {
        uint8_t* data = reinterpret_cast<uint8_t*>(buffer);
        size_t offset = 0;

        auto [suffix_pos, ptr_offset] = table.find_pointer(name);

        if (suffix_pos == 0) {
            // entire name can be compressed
            data[offset++] = 0xC0 | ((ptr_offset >> 8) & 0x3F);
            data[offset++] = ptr_offset & 0xFF;
        } else {
            // record this name's position
            table.record_name(name, msg_offset);

            // write full domain name as labels
            size_t pos = 0;
            while (pos < name.size()) {
                size_t dot_pos = name.find('.', pos);
                if (dot_pos == std::string::npos) {
                    dot_pos = name.size();
                }
                uint8_t label_len = dot_pos - pos;
                data[offset++] = label_len;
                for (size_t i = pos; i < dot_pos; ++i) {
                    data[offset++] = name[i];
                }
                pos = dot_pos + 1;
            }
            data[offset++] = 0;  // null terminator
        }

        // TYPE
        data[offset++] = (type >> 8) & 0xFF;
        data[offset++] = type & 0xFF;
        // CLASS
        data[offset++] = (cl >> 8) & 0xFF;
        data[offset++] = cl & 0xFF;

        // TTL (big-endian, 4 bytes)
        data[offset++] = (ttl >> 24) & 0xFF;
        data[offset++] = (ttl >> 16) & 0xFF;
        data[offset++] = (ttl >> 8) & 0xFF;
        data[offset++] = ttl & 0xFF;

        // RDLENGTH
        data[offset++] = (rdlen >> 8) & 0xFF;
        data[offset++] = rdlen & 0xFF;

        // RDATA
        for (auto byte : rdata) {
            data[offset++] = byte;
        }

        return offset;
    }

    static DNSAnswer create_a_record(const std::string& domain, uint32_t ttl,
                                     uint8_t a, uint8_t b, uint8_t c,
                                     uint8_t d) {
        DNSAnswer ans;
        ans.name = domain;
        ans.type = 1;  // A record
        ans.cl = 1;
        ans.ttl = ttl;
        ans.rdlen = 4;
        ans.rdata = {a, b, c, d};
        return ans;
    }

    size_t parse_from(const char* msg_start, const char* current_pos) {
        auto [parsed_name, name_bytes] =
            parse_domain_name(msg_start, current_pos);
        name = parsed_name;
        const uint8_t* data = reinterpret_cast<const uint8_t*>(current_pos);
        size_t offset = name_bytes;

        type = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        cl = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        ttl = (data[offset] << 24) | (data[offset + 1] << 16) |
              (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        rdlen = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        rdata.clear();
        for (uint16_t i = 0; i < rdlen; ++i) {
            rdata.push_back(data[offset + i]);
        }
        offset += rdlen;

        return offset;
    }
};

ssize_t forward_dns_query(const char* query_buf, size_t query_len,
                          char* response_buf, size_t respone_buf_size,
                          const std::string& resovler_ip,
                          uint16_t resolver_port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) return -1;

    struct sockaddr_in resolver_addr{};
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(resolver_port);
    // inet_pton: converts human-readable IP address into compact binary
    // network format
    inet_pton(AF_INET, resovler_ip.c_str(), &resolver_addr.sin_addr);

    sendto(sock, query_buf, query_len, 0,
           reinterpret_cast<struct sockaddr*>(&resolver_addr),
           sizeof(resolver_addr));

    socklen_t addr_len = sizeof(resolver_addr);
    ssize_t received =
        recvfrom(sock, response_buf, respone_buf_size, 0,
                 reinterpret_cast<struct sockaddr*>(&resolver_addr), &addr_len);

    close(sock);
    return received;
}

/**
 * Build single-question DNS query packet
 * Returns: length of the query packet
 */
size_t build_single_question_query(char* buffer, uint16_t id,
                                   const DNSQuestion& question,
                                   uint16_t original_flags) {
    DNSHeader header{};
    header.id = id;
    // keep original flags but ensure QR=0 (query)
    header.flags = original_flags & 0x7FFF;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    header.write_to(buffer);
    size_t offset = 12;
    offset += question.write_to(buffer + offset);

    return offset;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible
    // when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

    // parse command line argus for `--resolver`
    std::string resolver_ip{};
    uint16_t resolver_port = 0;
    bool use_forwarding = false;

    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--resolver" && i + 1 < argc) {
            std::string resolver_arg = argv[i + 1];
            size_t colon_pos = resolver_arg.find(':');
            if (colon_pos != std::string::npos) {
                resolver_ip = resolver_arg.substr(0, colon_pos);
                resolver_port = std::stoi(resolver_arg.substr(colon_pos + 1));
                use_forwarding = true;
            }
            break;
        }
    }

    if (use_forwarding) {
        std::cout << "DNS forwarder starting, resolver: " << resolver_ip << ":"
                  << resolver_port << std::endl;
    } else {
        std::cout << "DNS Server starting (standalone mode, returning 8.8.8.8)"
                  << std::endl;
    }

    int udpSocket;
    struct sockaddr_in clientAddress;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..."
                  << std::endl;
        return 1;
    }

    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
        0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(2053);
    // htonl: host to network long
    // converts 32-bit integer from host byte order to network byte order (big
    // endian)
    serv_addr.sin_addr = {htonl(INADDR_ANY)};

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr),
             sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int bytesRead;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);

    DNSCompressionTable compression;

    while (true) {
        // Receive data
        // recvfrom and sendto are specifically for UDP
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                             reinterpret_cast<struct sockaddr*>(&clientAddress),
                             &clientAddrLen);
        if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }

        buffer[bytesRead] = '\0';
        std::cout << "Received " << bytesRead << " bytes: " << buffer
                  << std::endl;

        DNSHeader query_header{};
        query_header.parse_from(buffer);

        std::vector<DNSQuestion> questions;
        const char* question_ptr = buffer + 12;  // after 12-byte header
        for (uint16_t i = 0; i < query_header.qdcount; ++i) {
            DNSQuestion q;
            size_t consumed = q.parse_from(buffer, question_ptr);
            questions.push_back(q);
            question_ptr += consumed;
        }

        // collect all answers from resolver(s)
        std::vector<DNSAnswer> all_answers;

        if (use_forwarding) {
            // forwarding mode: forward each question to resolver
            for (size_t i = 0; i < questions.size(); ++i) {
                char forward_query[512] = {};
                size_t forward_query_len = build_single_question_query(
                    forward_query, query_header.id, questions[i],
                    query_header.flags);
                char resolver_response[512] = {};
                // single-question query forwarded to resolver
                ssize_t resolver_bytes = forward_dns_query(
                    forward_query, forward_query_len, resolver_response,
                    sizeof(resolver_response), resolver_ip, resolver_port);

                if (resolver_bytes > 0) {
                    // parse the resolver response
                    DNSHeader resolver_header{};
                    resolver_header.parse_from(resolver_response);

                    // skip past header and question section in resolver
                    // response
                    const char* answer_ptr = resolver_response + 12;
                    for (uint16_t j = 0; j < resolver_header.qdcount; ++j) {
                        DNSQuestion q;
                        size_t consumed =
                            q.parse_from(resolver_response, answer_ptr);
                        answer_ptr += consumed;
                    }

                    // parse all answers
                    for (uint16_t k = 0; k < resolver_header.ancount; ++k) {
                        DNSAnswer ans;
                        size_t consumed =
                            ans.parse_from(resolver_response, answer_ptr);
                        all_answers.push_back(ans);
                        answer_ptr += consumed;
                    }
                }
            }

        } else {
            // standalone mode
            for (const auto& q : questions) {
                DNSAnswer ans =
                    DNSAnswer::create_a_record(q.qname, 60, 8, 8, 8, 8);
                all_answers.push_back(ans);
            }
        }

        DNSHeader response_header = DNSHeader::create_response(query_header);
        response_header.ancount = all_answers.size();

        char response[512] = {};
        response_header.write_to(response);
        size_t response_len = 12;

        // echo back the question section
        // record the name at offset 12
        // response_len += question.write_compressed_to(response + response_len,
        // response_len, compression);
        // uncompressed write back
        for (const auto& q : questions) {
            response_len += q.write_to(response + response_len);
        }

        // write answers uncompressed (one per question)
        for (const auto& ans : all_answers) {
            response_len += ans.write_to(response + response_len);
        }

        // Send response
        if (sendto(udpSocket, response, sizeof(response), 0,
                   reinterpret_cast<struct sockaddr*>(&clientAddress),
                   sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        }
    }

    close(udpSocket);

    return 0;
}
