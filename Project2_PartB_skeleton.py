import socket
import struct
import random
import json
import sys
from urllib import parse

# Example query spec as JSON
dns_query_spec = {
    "id": 1337,
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 1,      # recursion desired
    "questions": [
        {
            "qname": "princeton.edu",
            "qtype": 2,   # NS record
            "qclass": 1   # IN
        }
    ]
}


def build_query(query_spec):
    # Header fields
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Question section
    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  # end of qname
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            continue
        labels.append(data[offset+1:offset+1+length].decode())
        offset += length + 1

    if not jumped:
        return ".".join(labels), offset
    else:
        return ".".join(labels), original_offset

def parse_rr(data, offset):
    """Parse a single resource record and return record + new offset."""
    hostname, offset = parse_name(data, offset)
    atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10
    rdata = data[offset:offset+rdlength]
    offset += rdlength
    record={}
    record["hostname"] = hostname
    record["ttl"] = ttl
    record["atype"] = atype
    record["rtype"] = {1: "A", 2: "NS", 5: "CNAME", 28: "AAAA"}.get(atype, str(atype))
    record["ip"] = None
    record["nsname"] = None
    if atype == 1:
        record["ip"] = socket.inet_ntoa(rdata)
    elif atype == 28:
        record["ip"] = socket.inet_ntop(socket.AF_INET6, rdata)
    elif atype == 2:
        record["nsname"], _ = parse_name(data, offset - rdlength)
        #parse from the full data where rdata starts

    return record,offset


def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT
    response["nscount"] = NSCOUNT
    response["arcount"] = ARCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse Answer RRs
    answers = []
    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)
    response["answers"] = answers

    # Parse Authority RRs
    authorities = []
    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)
    response["authorities"] = authorities

    # Parse Additional RRs
    additionals = []
    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)
    response["additionals"] = additionals

    return response

def dns_query(query_spec, server=("8.8.8.8", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    response = parse_response(data)
    if response["tc"] == 1:
        raise RuntimeError("Response is truncated")
    if response["ra"] == 0:
        raise RuntimeError("Server does not support recursion")
    return response

if __name__ == "__main__":
    response = dns_query(dns_query_spec)
    print(json.dumps(response,indent=2))
    with open("dns_response.json", "w") as f:
        json.dump(response, f, indent=2)
    print("Response saved to dns_response.json")
