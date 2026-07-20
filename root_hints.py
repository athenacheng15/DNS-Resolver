from dns.records import ResourceRecord

TYPE_NAME_TO_NUM = {
    "A": 1,
    "NS": 2,
}

CLASS_NAME_TO_NUM = {
    "IN": 1,
}


def normalize_name(name):
    return name.lower()


def strip_comments(line):
    return line.split(";", 1)[0].strip()


def parse_root_hints(filename):
    root_ns_records = []
    root_a_records = []
    root_a_map = {}
    current_ttl = 0

    with open(filename, "r") as file:
        for line in file:
            line = strip_comments(line)

            if not line:
                continue

            parts = line.split()

            if parts[0].upper() == "$TTL":
                current_ttl = int(parts[1])
                continue

            record = parse_root_hints_line(parts, current_ttl)

            if record is None:
                continue

            if record.rtype == 2:
                root_ns_records.append(record)
            elif record.rtype == 1:
                root_a_records.append(record)
                key = normalize_name(record.name)

                if key not in root_a_map:
                    root_a_map[key] = []

                root_a_map[key].append(record)

    return root_ns_records, root_a_records, root_a_map


def parse_root_hints_line(parts, current_ttl):
    owner = parts[0]
    ttl = None
    rclass = 1
    rtype = None
    rdata = None

    i = 1

    while i < len(parts):
        token = parts[i]
        upper_token = token.upper()

        if upper_token == "IN":
            rclass = CLASS_NAME_TO_NUM["IN"]
        elif token.isdigit():
            ttl = int(token)
        elif upper_token in TYPE_NAME_TO_NUM:
            rtype = TYPE_NAME_TO_NUM[upper_token]

            if i + 1 >= len(parts):
                return None

            rdata = parts[i + 1]
            break

        i += 1

    if rtype is None:
        return None

    if rtype not in (1, 2):
        return None

    if ttl is None:
        ttl = current_ttl

    rdlength = 0

    return ResourceRecord(owner, rtype, rclass, ttl, rdlength, rdata)
