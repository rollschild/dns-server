#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>

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

        // build response flags
        // QR=1 (response)
        // OPCODE copied
        // AA=0
        // TC=0
        // RD copied
        // RA=0
        // Z=0
        // RCODE=0
        response.flags = (1 << 15) | (opcode << 11) | (rd << 8);

        response.qdcount = query.qdcount;
        response.ancount = 0;
        response.nscount = 0;
        response.arcount = 0;

        return response;
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

        DNSHeader response_header = DNSHeader::create_response(query_header);

        char response[512] = {};
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
