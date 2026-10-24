
import socket
import struct
import json

# Part C: Iterative DNS Resolver
dns_query_spec = {
    "id": 1337,
    "qr": 0,
    "opcode": 0,
    "rd": 0,  # Disable recursion
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,  # A record
            "qclass": 1  # Internet class
        }
    ]
}


def build_query(query_spec):
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    RD = query_spec["rd"] << 8

    flags = QR | OPCODE | RD

    QDCOUNT = len(query_spec["questions"])

    header = struct.pack(
        "!HHHHHH",
        ID, flags, QDCOUNT, 0, 0, 0
    )

    question_bytes = b""

    for q in query_spec["questions"]:
        labels = q["qname"].rstrip(".").split(".")

        for label in labels:
            encoded = label.encode("ascii")
            question_bytes += struct.pack("B", len(encoded))
            question_bytes += encoded

        question_bytes += b"\x00"
        question_bytes += struct.pack(
            "!HH", q["qtype"], q["qclass"]
        )

    return header + question_bytes


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset
    visited = set()

    while True:
        if offset >= len(data):
            raise ValueError("Invalid DNS name offset")

        if offset in visited:
            raise ValueError("DNS compression pointer loop")

        visited.add(offset)
        length = data[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("Invalid compression pointer")

            if not jumped:
                original_offset = offset + 2

            pointer = struct.unpack(
                "!H", data[offset:offset + 2]
            )[0]

            offset = pointer & 0x3FFF
            jumped = True
            continue

        if length & 0xC0:
            raise ValueError("Invalid DNS label")

        end = offset + 1 + length

        if end > len(data):
            raise ValueError("Invalid DNS label length")

        labels.append(
            data[offset + 1:end].decode("ascii")
        )
        offset = end

    if jumped:
        return ".".join(labels), original_offset

    return ".".join(labels), offset


def parse_rr(data, offset):
    hostname, offset = parse_name(data, offset)

    if offset + 10 > len(data):
        raise ValueError("Incomplete DNS resource record")

    atype, aclass, ttl, rdlength = struct.unpack(
        "!HHIH", data[offset:offset + 10]
    )

    offset += 10

    rdata_start = offset
    rdata_end = offset + rdlength

    if rdata_end > len(data):
        raise ValueError("Incomplete DNS record data")

    rdata = data[rdata_start:rdata_end]
    offset = rdata_end

    record = {
        "hostname": hostname,
        "ttl": ttl,
        "atype": atype,
        "rtype": {
            1: "A",
            2: "NS",
            5: "CNAME",
            28: "AAAA"
        }.get(atype, str(atype)),
        "ip": None,
        "nsname": None
    }

    if atype == 1 and rdlength == 4:
        record["ip"] = socket.inet_ntoa(rdata)

    elif atype == 28 and rdlength == 16:
        record["ip"] = socket.inet_ntop(
            socket.AF_INET6, rdata
        )

    elif atype == 2:
        record["nsname"], _ = parse_name(
            data, rdata_start
        )

    elif atype == 5:
        record["cname"], _ = parse_name(
            data, rdata_start
        )

    return record, offset


def parse_response(data):
    if len(data) < 12:
        raise ValueError("DNS response is too short")

    (
        ID, flags, QDCOUNT,
        ANCOUNT, NSCOUNT, ARCOUNT
    ) = struct.unpack("!HHHHHH", data[:12])

    response = {
        "id": ID,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "rcode": flags & 0xF,
        "qdcount": QDCOUNT,
        "ancount": ANCOUNT,
        "nscount": NSCOUNT,
        "arcount": ARCOUNT
    }

    offset = 12

    # Skip the Question section
    for _ in range(QDCOUNT):
        _, offset = parse_name(data, offset)
        offset += 4

        if offset > len(data):
            raise ValueError("Incomplete DNS question")

    # Parse Answer records
    answers = []

    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)

    # Parse Authority records
    authorities = []

    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)

    # Parse Additional records
    additionals = []

    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)

    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals

    return response


def receive_exact(sock, count):
    result = b""

    while len(result) < count:
        chunk = sock.recv(count - len(result))

        if not chunk:
            raise ConnectionError(
                "TCP connection closed unexpectedly"
            )

        result += chunk

    return result


def dns_query(query_spec, server):
    query = build_query(query_spec)

    # First, send the query using UDP
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(5)

    try:
        sock.sendto(query, server)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    response = parse_response(data)

    # Retry with TCP if the UDP response was truncated
    if response["tc"] == 1:
        print(
            "UDP response truncated. Retrying with TCP..."
        )

        tcp_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        tcp_sock.settimeout(5)

        try:
            tcp_sock.connect(server)

            # DNS over TCP uses a 2-byte length prefix
            tcp_sock.sendall(
                struct.pack("!H", len(query)) + query
            )

            response_length = struct.unpack(
                "!H", receive_exact(tcp_sock, 2)
            )[0]

            data = receive_exact(
                tcp_sock, response_length
            )

        finally:
            tcp_sock.close()

        response = parse_response(data)

    if response["id"] != query_spec["id"]:
        raise ValueError(
            "DNS transaction ID does not match"
        )

    if response["qr"] != 1:
        raise ValueError(
            "Received packet is not a DNS response"
        )

    if response["tc"] == 1:
        raise RuntimeError(
            "DNS response is still truncated"
        )

    return response


def iterative_resolve(query_spec):
    # Begin with a root DNS server
    servers = ["198.41.0.4"]

    print("Starting iterative DNS resolution")
    print("Root servers:", servers)

    visited = set()
    max_queries = 30
    query_count = 0

    while servers and query_count < max_queries:
        server_ip = servers.pop(0)

        if server_ip in visited:
            continue

        visited.add(server_ip)
        query_count += 1

        print("\nQuerying DNS server:", server_ip)

        try:
            response = dns_query(
                query_spec, (server_ip, 53)
            )

        except (
            socket.timeout,
            OSError,
            ValueError,
            RuntimeError
        ) as error:
            print("Query failed:", error)
            continue

        if response["rcode"] != 0:
            print(
                "DNS error code:", response["rcode"]
            )
            return response

        # Check for the requested A record
        for answer in response["answers"]:
            if (
                answer["atype"]
                == query_spec["questions"][0]["qtype"]
                and answer["ip"] is not None
            ):
                print(
                    "Found IP address:", answer["ip"]
                )
                return response

        # Get the names of the referred DNS servers
        ns_names = {
            record["nsname"].lower()
            for record in response["authorities"]
            if (
                record["atype"] == 2
                and record["nsname"]
            )
        }

        # Find glue IPv4 addresses for those servers
        new_servers = []

        for record in response["additionals"]:
            if (
                record["atype"] == 1
                and record["ip"] is not None
                and record["hostname"].lower() in ns_names
                and record["ip"] not in visited
            ):
                new_servers.append(record["ip"])

        if new_servers:
            print(
                "Following referral to:", new_servers
            )

            servers = new_servers + servers

        else:
            print(
                "No usable glue IP addresses in this response"
            )

    return {
        "error": "Resolution failed or no usable glue found"
    }


if __name__ == "__main__":
    response = iterative_resolve(dns_query_spec)

    print("\nFinal response:")
    print(json.dumps(response, indent=2))
