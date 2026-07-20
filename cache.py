import threading
import time


from utils import normalize_name


def make_cache_key(question):
    return (normalize_name(question.qname), question.qtype, question.qclass)
