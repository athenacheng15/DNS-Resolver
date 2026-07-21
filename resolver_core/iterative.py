from dns.records import DNSQuestion
from resolver_core.constants import (
    CLASS_IN,
    MAX_CNAME_RECORDS,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_CNAME,
)
from resolver_core.helpers import (
    extract_cname_chain_and_final_answers,
    get_complete_a_addresses,
    get_matching_glue_ips,
    get_referral_records,
    has_complete_positive_answer,
    is_authoritative_nodata_response,
    is_referral_response,
    make_resolution_result,
)
from resolver_core.models import ResolutionBudget, ResolutionLimitError
from resolver_core.upstream import query_upstream_candidate
from utils import normalize_name


def is_usable_upstream_response(message, question):
    """Return whether a response can advance or finish this lookup."""
    if message.header.rcode == RCODE_NXDOMAIN:
        return message.header.aa == 1

    if message.header.rcode != RCODE_NOERROR:
        return False

    response_cnames, final_answers, _ = extract_cname_chain_and_final_answers(
        message,
        question,
    )

    if message.header.aa == 1:
        return bool(response_cnames or final_answers) or is_authoritative_nodata_response(
            message,
            question,
        )

    return is_referral_response(message, question)


def resolve_next_name_server_addresses(
    ns_records,
    start_index,
    root_server_ips,
    timeout,
    budget,
):
    """Resolve the next referred NS name with usable IPv4 addresses."""
    for index in range(start_index, len(ns_records)):
        ns_record = ns_records[index]
        ns_question = DNSQuestion(qname=ns_record.rdata, qtype=TYPE_A, qclass=CLASS_IN)

        # Starting a no-glue nested NS hostname lookup consumes
        # one referral level from the shared resolution budget.
        budget.use_referral_level()

        nested_result = iterative_resolve(
            ns_question,
            root_server_ips,
            timeout,
            budget,
        )

        if nested_result is None:
            continue

        if nested_result["rcode"] != RCODE_NOERROR:
            continue

        addresses = get_complete_a_addresses(ns_record.rdata, nested_result["answers"])

        if addresses:
            return addresses, index + 1

    return [], len(ns_records)


def iterative_resolve(question, root_server_ips, timeout, budget):

    current_question = DNSQuestion(
        qname=normalize_name(question.qname),
        qtype=question.qtype,
        qclass=question.qclass,
    )

    candidate_ips = list(root_server_ips)

    cname_chain = []
    visited_cname_names = {normalize_name(question.qname)}
    uses_multiple_answer_responses = False
    pending_ns_records = []
    pending_ns_index = 0

    while candidate_ips:
        budget.ensure_time_remaining()

        upstream_result = query_upstream_candidate(
            candidate_ips,
            current_question,
            timeout,
            budget,
            accept_response=lambda message: is_usable_upstream_response(
                message,
                current_question,
            ),
        )

        if upstream_result is None:
            if pending_ns_index < len(pending_ns_records):
                candidate_ips, pending_ns_index = resolve_next_name_server_addresses(
                    pending_ns_records,
                    pending_ns_index,
                    root_server_ips,
                    timeout,
                    budget,
                )

                if candidate_ips:
                    continue

            return None

        message = upstream_result["message"]
        pending_ns_records = []
        pending_ns_index = 0
        client_response_aa = (
            0 if uses_multiple_answer_responses else message.header.aa
        )

        # NXDOMAIN is final only when returned by an authoritative server.
        if message.header.aa == 1 and message.header.rcode == RCODE_NXDOMAIN:
            return make_resolution_result(
                answers=list(cname_chain),
                authorities=[],
                additional=[],
                rcode=RCODE_NXDOMAIN,
                aa=client_response_aa,
            )

        # Other upstream errors currently fail this resolution.
        if message.header.rcode != RCODE_NOERROR:
            return None

        response_cnames, final_answers, terminal_name = (
            extract_cname_chain_and_final_answers(message, current_question)
        )

        # Direct CNAME query:
        # extract_cname_chain_and_final_answers() returns the requested
        # CNAME RRset as final_answers and does not chase its target.
        if current_question.qtype == TYPE_CNAME:
            if final_answers:
                return make_resolution_result(
                    answers=final_answers,
                    authorities=[],
                    additional=[],
                    rcode=RCODE_NOERROR,
                    aa=client_response_aa,
                )

            # Stop if this is an authoritative NODATA response.
            if is_authoritative_nodata_response(message, current_question):
                return make_resolution_result(
                    answers=[],
                    authorities=[],
                    additional=[],
                    rcode=RCODE_NOERROR,
                    aa=client_response_aa,
                )

        # For A, NS, MX, and PTR queries, process any CNAME records found
        # in this response before checking for authoritative NODATA.
        if response_cnames:
            if len(cname_chain) + len(response_cnames) > MAX_CNAME_RECORDS:
                raise ResolutionLimitError("CNAME chain limit reached")

            expected_owner = normalize_name(current_question.qname)

            for cname_record in response_cnames:
                owner_name = normalize_name(cname_record.name)
                target_name = normalize_name(cname_record.rdata)

                # The extracted chain should continue from the current name.
                if owner_name != expected_owner:
                    raise ValueError("CNAME chain owner does not match expected name")

                if target_name in visited_cname_names:
                    raise ResolutionLimitError("CNAME loop detected")

                cname_chain.append(cname_record)
                visited_cname_names.add(target_name)
                expected_owner = target_name

        # The same response may already contain the complete CNAME chain
        # followed by the requested-type RRset.
        if final_answers:
            return make_resolution_result(
                answers=cname_chain + final_answers,
                authorities=[],
                additional=[],
                rcode=RCODE_NOERROR,
                aa=client_response_aa,
            )

        # A CNAME chain was found, but this response did not contain the
        # final requested-type RRset. Restart iterative resolution from
        # the root for the canonical target, preserving the original type.
        if response_cnames:
            uses_multiple_answer_responses = True
            current_question = DNSQuestion(
                qname=terminal_name,
                qtype=question.qtype,
                qclass=question.qclass,
            )
            candidate_ips = list(root_server_ips)
            continue

        # No requested answer and no CNAME remain. If the response is
        # authoritative, this is terminal NODATA rather than a referral.
        if is_authoritative_nodata_response(message, current_question):
            return make_resolution_result(
                answers=list(cname_chain),
                authorities=[],
                additional=[],
                rcode=RCODE_NOERROR,
                aa=client_response_aa,
            )

        if not is_referral_response(message, current_question):
            return None

        budget.use_referral_level()

        ns_records = get_referral_records(message, current_question)
        glue_ips = get_matching_glue_ips(message, ns_records)

        if glue_ips:
            candidate_ips = glue_ips
        else:
            # Resolve NS hostnames from the root when no glue is available.
            budget.ensure_time_remaining()
            pending_ns_records = ns_records
            candidate_ips, pending_ns_index = resolve_next_name_server_addresses(
                pending_ns_records,
                0,
                root_server_ips,
                timeout,
                budget,
            )

        if not candidate_ips:
            return None

    return None


def resolve_client_question(question, root_server_ips, timeout, cache):
    """
    Resolve one client question using the shared positive-answer cache.

    A complete unexpired cached answer is returned without sending any
    upstream DNS packets. On a cache miss, iterative resolution is used.

    Only complete positive NOERROR answers are inserted into the cache.
    NXDOMAIN, NODATA, SERVFAIL, and incomplete CNAME chains are not cached.
    """

    cache_answers = cache.get(question)
    if cache_answers is not None:
        return make_resolution_result(
            answers=cache_answers,
            authorities=[],
            additional=[],
            rcode=RCODE_NOERROR,
        )

    budget = ResolutionBudget(timeout)
    try:
        resolution_result = iterative_resolve(
            question, root_server_ips, timeout, budget
        )
    except (ResolutionLimitError, ValueError):
        return None

    if resolution_result is None:
        return None

    if resolution_result["rcode"] == RCODE_NOERROR and has_complete_positive_answer(
        question, resolution_result["answers"]
    ):
        cache.put(question, resolution_result["answers"])
        return resolution_result

    return resolution_result
