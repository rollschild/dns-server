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
 * Returns: {parsed_name, bytes_consumed_at_current_position}
 */
std::pair<std::string, size_t> parse_domain_name(const char* msg_start,
                                                 const char* current_pos) {
    const uint8_t* msg = reinterpret_cast<const uint8_t*>(msg_start);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(current_pos);
    std::string name;
    size_t offset = 0;
    size_t bytes_consumed = 0;
    bool jumped = false;  // TODO: what is this?

    while (true) {
        uint8_t len = data[offset];
        if (len == 0) {
            // end of name
            if (!jumped) {
                bytes_consumed = offset + 1;
            }
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            // compression pointer: 2 bytes, upper 2 bits are `11`
            if (!jumped) {
                bytes_consumed = offset + 2;  // only count first pointer
            }
            uint16_t ptr = ((len & 0x2F) << 8) | data[offset + 1];
            data = msg + ptr;  // jump to pointed location
            offset = 0;        // TODO: why?
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
};

int main() {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible
    // when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

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

        DNSHeader response_header = DNSHeader::create_response(query_header);

        char response[512] = {};
        response_header.write_to(response);
        size_t response_len = 12;

        // echo back the question section
        // record the name at offset 12
        // response_len += question.write_to(response + response_len,
        // response_len, compression);
        // uncompressed write back
        for (const auto& q : questions) {
            response_len += q.write_to(response + response_len);
        }

        // write answers uncompressed (one per question)
        std::vector<DNSAnswer> answers;
        for (const auto& q : questions) {
            DNSAnswer ans = DNSAnswer::create_a_record(q.qname, 60, 8, 8, 8, 8);
            // use compression pointer to question's name
            // response_len +=
            // ans.write_to(response + response_len, response_len, compression);
            response_len += ans.write_to(response + response_len);
            answers.push_back(ans);
        }

        // update header to reflect 1 answer
        response_header.ancount = answers.size();
        // re-write header with updated ancount (account number)
        response_header.write_to(response);

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
