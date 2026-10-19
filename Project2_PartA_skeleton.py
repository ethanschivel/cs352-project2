
import socket
import struct
import json


DNS_SERVER = ("8.8.8.8", 53)
DNS_TRANSACTION_ID = 1337


def build_query(query_spec):
    """Build a DNS query packet."""

    dns_id = query_spec["id"]
    qr = query_spec["qr"]
    opcode = query_spec["opcode"]
    rd = query_spec["rd"]

    # Set DNS header flags.
    flags = (
        (qr << 15)
        | (opcode << 11)
        | (rd << 8)
    )

    questions = query_spec["questions"]

    # DNS header: ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    header = struct.pack(
        "!HHHHHH",
        dns_id,
        flags,
        len(questions),
        0,
        0,
        0
    )

    question_bytes = b""

    for question in questions:
        # Remove a trailing dot, if the domain has one.
        qname = question["qname"].rstrip(".")
        labels = qname.split(".")

        # Encode each domain label as length followed by bytes.
        for label in labels:
            label_bytes = label.encode("ascii")

            if len(label_bytes) > 63:
                raise ValueError("DNS label is too long")

            question_bytes += struct.pack("!B", len(label_bytes))
            question_bytes += label_bytes

        # End the domain name with a zero byte.
        question_bytes += b"\x00"

        # QTYPE and QCLASS.
        qtype = question["qtype"]
        qclass = question.get("qclass", 1)

        question_bytes += struct.pack("!HH", qtype, qclass)

    return header + question_bytes


def skip_name(data, offset):
    """Skip a DNS name, including a compressed name pointer."""

    while True:
        length = data[offset]

        # Compression pointer: the first two bits are 11.
        if (length & 0xC0) == 0xC0:
            return offset + 2

        # Zero marks the end of the name.
        if length == 0:
            return offset + 1

        # Move past this label's length byte and contents.
        offset += 1 + length


def parse_response(data):
    """Parse the DNS header, question section, and answer section."""

    if len(data) < 12:
        raise ValueError("DNS response is shorter than its header")

    (
        dns_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    ) = struct.unpack("!HHHHHH", data[:12])

    response = {
        "id": dns_id,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0x0F,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "rcode": flags & 0x0F,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }

    # Skip all question entries.
    offset = 12

    for _ in range(qdcount):
        offset = skip_name(data, offset)

        # Each question ends with QTYPE (2 bytes) and QCLASS (2 bytes).
        offset += 4

    answers = []

    # Parse every resource record in the answer section.
    for _ in range(ancount):
        # Skip the answer's NAME, which may be compressed.
        offset = skip_name(data, offset)

        # TYPE (2), CLASS (2), TTL (4), RDLENGTH (2).
        if offset + 10 > len(data):
            raise ValueError("Incomplete DNS resource record")

        atype, aclass, ttl, rdlength = struct.unpack(
            "!HHIH",
            data[offset:offset + 10]
        )

        offset += 10

        # Make sure the RDATA bytes are present.
        if offset + rdlength > len(data):
            raise ValueError("Incomplete DNS RDATA")

        rdata = data[offset:offset + rdlength]
        offset += rdlength

        # Extract IPv4 A records.
        if atype == 1 and aclass == 1 and rdlength == 4:
            ip = socket.inet_ntop(socket.AF_INET, rdata)

        # Extract IPv6 AAAA records.
        elif atype == 28 and aclass == 1 and rdlength == 16:
            ip = socket.inet_ntop(socket.AF_INET6, rdata)

        # Ignore record types Part A doesn't extract.
        else:
            continue

        answer = {
            "type": atype,
            "ip": ip,
            "ttl": ttl
        }

        answers.append(answer)

    response["answers"] = answers

    return response


def dns_query(query_spec, server=DNS_SERVER):
    """Send a DNS query to a recursive resolver and parse its response."""

    query = build_query(query_spec)

    # Create a UDP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(query, server)

        # Receive the DNS response.
        data, _ = sock.recvfrom(512)

    finally:
        sock.close()

    result = parse_response(data)

    # Verify that this is a DNS response to our query.
    if result["qr"] != 1:
        raise RuntimeError("Received a DNS packet that is not a response")

    if result["id"] != query_spec["id"]:
        raise RuntimeError("DNS transaction ID does not match")

    # The assignment requires an error for truncated responses.
    if result["tc"] == 1:
        raise RuntimeError("DNS response is truncated (TC=1)")

    # Part A requires a recursive resolver that supports recursion.
    if result["ra"] != 1:
        raise RuntimeError("DNS server does not support recursion (RA=0)")

    if result["rcode"] != 0:
        raise RuntimeError(
            f"DNS returned an error response: RCODE={result['rcode']}"
        )

    return result


def make_query_spec(qname, qtype):
    """Create the query specification for one input question."""

    return {
        "id": DNS_TRANSACTION_ID,
        "qr": 0,
        "opcode": 0,
        "rd": 1,
        "questions": [
            {
                "qname": qname,
                "qtype": qtype,
                "qclass": 1
            }
        ]
    }


def main():
    # Read the test questions from input.txt.
    with open("input.txt", "r") as file:
        query_json = json.load(file)

    all_responses = []

    # Resolve each question in the input file.
    for question in query_json["questions"]:
        qname = question["qname"]
        qtype = question["qtype"]

        query_spec = make_query_spec(qname, qtype)

        print(f"Querying {qname}, type {qtype}...")

        response = dns_query(query_spec)

        # Print this response to the terminal.
        print(json.dumps(response, indent=2))

        all_responses.append(response)

    # Save the responses from this run to output.txt.
    with open("output.txt", "w") as file:
        json.dump(all_responses, file, indent=2)

    print("DNS responses saved to output.txt")


if __name__ == "__main__":
    main()
