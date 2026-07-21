import socket
import time

from dns.encoder import encode_upstream_query
from dns.message import parse_dns_message
from resolver_core.constants import (
    MAX_RECEIVED_DNS_MESSAGE_SIZE,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    UPSTREAM_DNS_PORT,
)
from resolver_core.helpers import question_match


def is_retryable_upstream_response(message):
    """
    Return True when a valid upstream DNS response should be treated as a
    failure for this candidate server.

    NOERROR responses may contain a final answer, NODATA, CNAME, or referral.
    NXDOMAIN may be terminal when authoritative, so it must be examined by
    iterative_resolve().
    """
    if message.header.rcode == RCODE_NXDOMAIN:
        return message.header.aa != 1

    return message.header.rcode != RCODE_NOERROR

def validate_upstream_response(
    response_data,
    response_address,
    expected_server_ip,
    expected_transaction_id,
    expected_question,
):

    source_ip, source_port = response_address

    # The response must come from the server that was queried.
    if source_ip != expected_server_ip:
        raise ValueError("Upstream response came from the wrong IP address")

    # DNS servers must respond from port 53.
    if source_port != UPSTREAM_DNS_PORT:
        raise ValueError("Upstream response came from the wrong port")

    message = parse_dns_message(response_data)
    header = message.header

    if header.message_id != expected_transaction_id:
        raise ValueError("Upstream response has the wrong transaction ID")
    if header.qr != 1:
        raise ValueError("Upstream response is not a DNS response")
    if header.opcode != 0:
        raise ValueError("Upstream response has an unsupported OPCODE")

    # Do not retry with TCP. A truncated UDP response makes this
    # candidate fail.
    if header.tc != 0:
        raise ValueError("Upstream response is truncated")

    if header.qdcount != 1:
        raise ValueError("Upstream response must contain exactly one question")

    if len(message.questions) != 1:
        raise ValueError("Parsed question count does not match QDCOUNT")

    if not question_match(
        message.questions[0],
        expected_question,
    ):
        raise ValueError("Upstream response question does not match the query")

    return message

def query_upstream_server(server_ip, question, timeout, budget):
    """
    Send one DNS query to one upstream server.

    The function waits no longer than both:
    - the configured timeout for one upstream attempt, and
    - the remaining wall-clock budget for the complete client resolution.

    Invalid or unrelated UDP datagrams are ignored while the same attempt
    deadline remains active.
    """
    budget.ensure_time_remaining()
    transaction_id, query_data = encode_upstream_query(question)

    upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    now = time.monotonic()
    attempt_deadline = min(now + timeout, budget.deadline)

    try:
        upstream_socket.sendto(query_data, (server_ip, UPSTREAM_DNS_PORT))
        while True:
            remaining_time = attempt_deadline - time.monotonic()
            if remaining_time <= 0:
                return None

            upstream_socket.settimeout(remaining_time)

            try:
                response_data, response_address = upstream_socket.recvfrom(
                    MAX_RECEIVED_DNS_MESSAGE_SIZE
                )
            except socket.timeout:
                return None
            try:
                message = validate_upstream_response(
                    response_data, response_address, server_ip, transaction_id, question
                )
            except ValueError:
                continue  # Ignore invalid or unrelated UDP datagrams and keep waiting until the original timeout deadline.

            return {
                "transaction_id": transaction_id,
                "response_data": response_data,
                "response_address": response_address,
                "message": message,
            }
    finally:
        upstream_socket.close()

def query_upstream_candidate(
    server_ips,
    question,
    timeout,
    budget,
    accept_response=None,
):
    """
    Query candidate upstream servers sequentially.

    Each attempted server consumes one outbound-attempt unit. Timeouts,
    invalid packets, and retryable DNS error responses cause the resolver
    to continue with the next candidate.
    """
    for server_ip in server_ips:
        budget.use_outbound_attempt()

        try:
            result = query_upstream_server(server_ip, question, timeout, budget)
        except OSError:
            # A socket failure only makes this candidate unusable. Other
            # candidates should still be attempted within the shared budget.
            continue

        if result is None:
            continue

        if is_retryable_upstream_response(result["message"]):
            continue

        if accept_response is not None:
            try:
                if not accept_response(result["message"]):
                    continue
            except ValueError:
                # A semantically malformed response only fails this
                # candidate; another server may still provide a usable one.
                continue

        return result

    return None
