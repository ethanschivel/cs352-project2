
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
            "qtype": 1,   # A record
            "qclass": 1   # Internet class
        }
    ]
}


def build_query(query_spec):
    query_id = query_spec["id"]

    flags = (
        (query_spec["qr"] << 15)
        | (query_spec["opcode"] << 11)
        | (query_spec["rd"] << 8)
    )

    questions = query_spec["questions"]

    header = struct.pack(
        "!HHHHHH",
        query_id,
        flags,
        len(questions),
        0,
        0,
        0
    )

    question_bytes = b""

    for question in questions:
        domain = question["qname"].rstrip(".")

        for label in domain.split("."):
            encoded = label.encode("ascii")

            if len(encoded) > 63:
                raise ValueError("DNS label is too long")

            question_bytes += bytes([len(encoded)])
            question_bytes += encoded

        question_bytes += b"\x00"

        question_bytes += struct.pack(
            "!HH",
            question["qtype"],
            question["qclass"]
        )

    return header + question_bytes


def parse_name(data, offset):
    labels = []
    jumped = False
    next_offset = offset
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

            if not jumped:
                next_offset = offset

            break

        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("Invalid compression pointer")

            pointer = struct.unpack(
                "!H",
                data[offset:offset + 2]
            )[0]

            if not jumped:
                next_offset = offset + 2

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

        if not jumped:
            next_offset = offset

    return ".".join(labels), next_offset


def parse_rr(data, offset):
    hostname, offset = parse_name(data, offset)

    if offset + 10 > len(data):
        raise ValueError("Incomplete DNS resource record")

    atype, aclass, ttl, rdlength = struct.unpack(
        "!HHIH",
        data[offset:offset + 10]
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
        "aclass": aclass,
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
            socket.AF_INET6,
            rdata
        )

    elif atype == 2:
        record["nsname"], _ = parse_name(
            data,
            rdata_start
        )

    elif atype == 5:
        record["cname"], _ = parse_name(
            data,
            rdata_start
        )

    return record, offset


def parse_response(data):
    if len(data) < 12:
        raise ValueError("DNS response is too short")

    (
        query_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    ) = struct.unpack("!HHHHHH", data[:12])

    response = {
        "id": query_id,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "rcode": flags & 0xF,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount
    }

    # Professor's requirement:
    # Stop immediately if the DNS response is truncated.
    if response["tc"] == 1:
        raise RuntimeError(
            "DNS response was truncated (TC=1)"
        )

    offset = 12

    # Skip the Question section
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)

        if offset + 4 > len(data):
            raise ValueError("Incomplete DNS question")

        offset += 4

    # Parse Answer records
    answers = []

    for _ in range(ancount):
        record, offset = parse_rr(data, offset)
        answers.append(record)

    # Parse Authority records
    authorities = []

    for _ in range(nscount):
        record, offset = parse_rr(data, offset)
        authorities.append(record)

    # Parse Additional records
    additionals = []

    for _ in range(arcount):
        record, offset = parse_rr(data, offset)
        additionals.append(record)

    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals

    return response


def dns_query(query_spec, server_ip):
    query = build_query(query_spec)

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(5)

    try:
        sock.sendto(query, (server_ip, 53))
        data, source = sock.recvfrom(4096)
    finally:
        sock.close()

    # Validate the DNS response header.
    if len(data) < 12:
        raise ValueError("DNS response is too short")

    response_id, flags = struct.unpack(
        "!HH",
        data[:4]
    )

    if response_id != query_spec["id"]:
        raise ValueError(
            "DNS transaction ID does not match"
        )

    if ((flags >> 15) & 1) != 1:
        raise ValueError(
            "Received packet is not a DNS response"
        )

    # No TCP retry. Stop on TC=1.
    if ((flags >> 9) & 1) == 1:
        raise RuntimeError(
            "DNS response was truncated (TC=1)"
        )

    return parse_response(data)


def iterative_resolve(query_spec):
    # Start with B-root instead of A-root.
    servers = ["199.9.14.201"]

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
                query_spec,
                server_ip
            )

        except RuntimeError as error:
            # A truncated response must stop the resolution.
            print("Resolution stopped:", error)

            return {
                "error": str(error),
                "server": server_ip,
                "queries_sent": query_count
            }

        except (socket.timeout, OSError, ValueError) as error:
            print("Query failed:", error)

            return {
                "error": str(error),
                "server": server_ip,
                "queries_sent": query_count
            }

        if response["rcode"] != 0:
            return {
                "error": "DNS server returned an error",
                "rcode": response["rcode"],
                "server": server_ip
            }

        # Look for the requested IP address.
        requested_type = query_spec["questions"][0]["qtype"]

        for answer in response["answers"]:
            if (
                answer["atype"] == requested_type
                and answer["ip"] is not None
            ):
                print("Found IP address:", answer["ip"])
                print("Queries sent:", query_count)

                return response

        # Collect NS records from the Authority section.
        ns_names = {
            record["nsname"].lower()
            for record in response["authorities"]
            if (
                record["atype"] == 2
                and record["nsname"] is not None
            )
        }

        # Find IPv4 glue records for those name servers.
        new_servers = []

        for record in response["additionals"]:
            if (
                record["atype"] == 1
                and record["ip"] is not None
                and record["hostname"].lower() in ns_names
                and record["ip"] not in visited
                and record["ip"] not in new_servers
            ):
                new_servers.append(record["ip"])

        if new_servers:
            print("Following referral to:", new_servers)
            servers = new_servers + servers

        else:
            return {
                "error": "No usable glue IP addresses found",
                "server": server_ip,
                "queries_sent": query_count
            }

    return {
        "error": "Resolution failed or maximum queries reached",
        "queries_sent": query_count
    }


if __name__ == "__main__":
    result = iterative_resolve(dns_query_spec)

    print("\nFinal response:")
    print(json.dumps(result, indent=2))
