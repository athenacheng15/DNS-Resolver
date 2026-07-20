import time

from resolver_core.constants import (
    MAX_OUTBOUND_ATTEMPTS,
    MAX_REFERRAL_LEVELS,
    MAX_RESOLUTION_SECONDS,
)


class ResolutionLimitError(Exception):
    pass

class ResolutionBudget:
    """
    Track limits shared by one complete client resolution.

    The same budget is reused by:
    - the original iterative lookup,
    - nested name-server address lookups,
    - CNAME chasing.

    This ensures all work triggered by one client query shares the same
    outbound-attempt, referral-level, and wall-clock limits.
    """

    def __init__(self, timeout):
        self.outbound_attempts = 0
        self.referral_levels = 0

        total_time_limit = min(MAX_RESOLUTION_SECONDS, MAX_OUTBOUND_ATTEMPTS * timeout)
        self.deadline = time.monotonic() + total_time_limit

    def remaining_time(self):
        """
        Return the number of seconds remaining for this client resolution.
        The returned value may be zero when the overall deadline has passed.
        """

        return max(0.0, self.deadline - time.monotonic())

    def ensure_time_remaining(self):
        """
        Raise ResolutionLimitError when the total resolution deadline expires.
        """
        if self.remaining_time() <= 0:
            raise ResolutionLimitError("Total resolution time limit reached")

    def use_outbound_attempt(self):
        self.ensure_time_remaining()
        if self.outbound_attempts >= MAX_OUTBOUND_ATTEMPTS:
            raise ResolutionLimitError("Outbound attempts limit reached")
        self.outbound_attempts += 1

    def use_referral_level(self):
        self.ensure_time_remaining()
        if self.referral_levels >= MAX_REFERRAL_LEVELS:
            raise ResolutionLimitError("Referral levels limit reached")
        self.referral_levels += 1
