# DNS Server

DNS server communicates over **UDP**.

All communications in DNS protocol are carried in a single format, **message**.

Each message consists of 5 sections:

- header
  - _always_ 12 bytes long
  - big endian
- question
- answer
- authority
- an additional space

```
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
```
