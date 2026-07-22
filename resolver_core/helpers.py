from constants import (
    CLASS_IN,
    MAX_CNAME_RECORDS,
    RCODE_NOERROR,
    SUPPORTED_RECORD_TYPES,
    TYPE_A,
    TYPE_CNAME,
    TYPE_NS,
)
from resolver_core.models import ResolutionLimitError
from utils import normalize_name


# DNS name and question matching


def is_supported_client_question(question):
    return question.qtype in SUPPORTED_RECORD_TYPES


def question_match(actual_question, expected_question):
    return (
        normalize_name(actual_question.qname) == normalize_name(expected_question.qname)
        and actual_question.qtype == expected_question.qtype
        and actual_question.qclass == expected_question.qclass
    )


def record_name_matches(actual_name, expected_name):
    return normalize_name(actual_name) == normalize_name(expected_name)


def name_is_within_zone(name, zone):
    name = normalize_name(name)
    zone = normalize_name(zone)

    if zone == ".":
        return True

    return name == zone or name.endswith("." + zone)


def zone_label_count(zone):
    zone = normalize_name(zone)

    if zone == ".":
        return 0

    return len(zone.rstrip(".").split("."))


# CNAME and answer handling


def find_requested_answer(message, question):
    return [
        record
        for record in message.answers
        if (
            record.rclass == question.qclass
            and record.rtype == question.qtype
            and record_name_matches(record.name, question.qname)
        )
    ]


def find_cname_answer(message, expected_name, expected_class):
    return [
        record
        for record in message.answers
        if (
            record.rclass == expected_class
            and record.rtype == TYPE_CNAME
            and record_name_matches(record.name, expected_name)
        )
    ]


def extract_cname_chain_and_final_answers(message, question):
    original_name = normalize_name(question.qname)

    # A direct CNAME query must return only the CNAME RRset whose owner is the original QNAME.
    # Its target must not be chased.
    if question.qtype == TYPE_CNAME:
        direct_answers = find_cname_answer(message, original_name, question.qclass)
        return [], direct_answers, original_name

    current_name = original_name
    visited_names = {current_name}
    cname_chain = []

    while True:
        final_answers = []
        for record in message.answers:
            if (
                record.rclass == question.qclass
                and record.rtype == question.qtype
                and record_name_matches(record.name, current_name)
            ):
                final_answers.append(record)

        if final_answers:
            return cname_chain, final_answers, current_name

        cname_records = find_cname_answer(message, current_name, question.qclass)
        if not cname_records:
            return cname_chain, [], current_name

        # A CNAME owner should point to one canonical target.
        target_name = normalize_name(cname_records[0].rdata)

        for record in cname_records:
            if normalize_name(record.rdata) != target_name:
                raise ValueError("Conflicting CNAME targets")

        if len(cname_chain) + len(cname_records) > MAX_CNAME_RECORDS:
            raise ResolutionLimitError("CNAME chain limit reached")

        if target_name in visited_names:
            raise ResolutionLimitError("CNAME loop detected")

        cname_chain.extend(cname_records)
        visited_names.add(target_name)
        current_name = target_name


def has_complete_positive_answer(question, records):
    # Return True when records form a complete positive answer for question.

    current_name = normalize_name(question.qname)
    visited_names = {current_name}
    cname_count = 0

    if question.qtype == TYPE_CNAME:
        for record in records:
            if (
                record.rclass == question.qclass
                and record.rtype == TYPE_CNAME
                and record_name_matches(record.name, current_name)
            ):
                return True
        return False

    while True:
        # Check whether the requested-type RRset exists for the current
        # canonical name.
        for record in records:
            if (
                record.rclass == question.qclass
                and record.rtype == question.qtype
                and record_name_matches(record.name, current_name)
            ):
                return True

        # Otherwise, find the next CNAME link.
        matching_cnames = []

        for record in records:
            if (
                record.rclass == question.qclass
                and record.rtype == TYPE_CNAME
                and record_name_matches(record.name, current_name)
            ):
                matching_cnames.append(record)

        if not matching_cnames:
            return False

        target_name = normalize_name(matching_cnames[0].rdata)

        # One alias owner must not point to conflicting targets.
        for record in matching_cnames:
            if normalize_name(record.rdata) != target_name:
                return False

        cname_count += len(matching_cnames)
        if cname_count > MAX_CNAME_RECORDS:
            return False

        if target_name in visited_names:
            return False

        visited_names.add(target_name)
        current_name = target_name


def get_complete_a_addresses(original_name, records):
    # Follow a complete CNAME chain starting at original_name
    # return the IPv4 addresses belonging to the final canonical name.
    current_name = normalize_name(original_name)
    visited_names = {current_name}
    cname_count = 0

    while True:
        addresses = []

        for record in records:
            if (
                record.rclass == CLASS_IN
                and record.rtype == TYPE_A
                and record_name_matches(
                    record.name,
                    current_name,
                )
            ):
                addresses.append(record.rdata)

        if addresses:
            return addresses

        matching_cnames = []

        for record in records:
            if (
                record.rclass == CLASS_IN
                and record.rtype == TYPE_CNAME
                and record_name_matches(
                    record.name,
                    current_name,
                )
            ):
                matching_cnames.append(record)

        if not matching_cnames:
            return []

        target_name = normalize_name(matching_cnames[0].rdata)

        # The same alias owner must not point to different targets.
        for record in matching_cnames:
            if normalize_name(record.rdata) != target_name:
                return []

        cname_count += len(matching_cnames)

        if cname_count > MAX_CNAME_RECORDS:
            return []

        if target_name in visited_names:
            return []

        visited_names.add(target_name)
        current_name = target_name


# Referral and glue handling


def get_referral_records(message, question):
    matching_records = []
    most_specific_label_count = -1

    for record in message.authority:
        if record.rclass != CLASS_IN:
            continue

        if record.rtype != TYPE_NS:
            continue

        delegated_zone = normalize_name(record.name)

        if not name_is_within_zone(
            question.qname,
            delegated_zone,
        ):
            continue

        label_count = zone_label_count(delegated_zone)

        if label_count > most_specific_label_count:
            matching_records = [record]
            most_specific_label_count = label_count

        elif label_count == most_specific_label_count:
            matching_records.append(record)

    return matching_records


def get_matching_glue_ips(message, ns_records):
    # Match glue records only for referred name servers.
    glue_ips = []
    for ns_record in ns_records:
        ns_name = normalize_name(ns_record.rdata)

        for additional_record in message.additional:
            if additional_record.rclass != CLASS_IN:
                continue
            if additional_record.rtype != TYPE_A:
                continue

            additional_name = normalize_name(additional_record.name)
            if additional_name == ns_name:
                glue_ips.append(additional_record.rdata)

    return glue_ips


def is_authoritative_nodata_response(message, question):
    return (
        message.header.aa == 1
        and message.header.rcode == RCODE_NOERROR
        and not find_requested_answer(message, question)
    )


def is_referral_response(message, question):
    if message.header.aa == 1:
        return False
    if message.header.rcode != RCODE_NOERROR:
        return False
    if find_requested_answer(message, question):
        return False

    return bool(get_referral_records(message, question))


# Resolution result and root hints


def filter_encodable_records(records):
    return [record for record in records if record.rtype in SUPPORTED_RECORD_TYPES]


def make_resolution_result(
    answers=None, authorities=None, additional=None, rcode=RCODE_NOERROR, aa=0
):
    return {
        "answers": [] if answers is None else answers,
        "authorities": [] if authorities is None else authorities,
        "additional": [] if additional is None else additional,
        "rcode": rcode,
        "aa": aa,
    }


def build_root_hints_response(question, root_ns_records, root_a_records, root_a_map):
    qname = normalize_name(question.qname)

    # Root hints only contains IN records
    if question.qclass != CLASS_IN:
        return None

    # Query: .NS
    if qname == "." and question.qtype == TYPE_NS:
        answers = list(root_ns_records)
        additional = []

        # For every returned NS record, find its matching A glue records in order.
        for ns_record in root_ns_records:
            ns_name = normalize_name(ns_record.rdata)

            for a_record in root_a_records:
                a_name = normalize_name(a_record.name)

                if a_name == ns_name:
                    additional.append(a_record)

        return make_resolution_result(
            answers=answers,
            additional=additional,
        )

    if question.qtype == TYPE_A:
        answers = root_a_map.get(qname, [])
        if answers:
            return make_resolution_result(
                answers=list(answers),
            )

    # This query cannot be answered using named.root.
    return None


def get_root_server_ips(root_ns_records, root_a_records):
    root_server_ips = []

    for ns_record in root_ns_records:
        ns_name = normalize_name(ns_record.rdata)

        for a_record in root_a_records:
            a_name = normalize_name(a_record.name)

            if a_name == ns_name:
                root_server_ips.append(a_record.rdata)

    return root_server_ips
