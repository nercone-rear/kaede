import pytest

from kaede.uds.api.server import UDSGate, UDSServerLimits

# UDSGate is admission control: a global cap on concurrent connections and a
# sliding-window cap on new connections. Unlike TCPGate there is no peer
# address to bucket by (every UDS peer is local), so the window is shared by
# all connections. The clock is injected so the windows can be checked
# exactly rather than by sleeping.

def gate(nums=1000, rate=None):
    limits = UDSServerLimits()
    limits.max_connection_nums = nums

    if rate is not None:
        limits.max_connection_rate = rate

    return UDSGate(limits)

class TestConnectionCount:
    def test_admits_up_to_the_limit(self):
        g = gate(nums=3, rate=[])

        assert [g.admit(now=0) for _ in range(3)] == [True, True, True]

    def test_refuses_beyond_the_limit(self):
        g = gate(nums=3, rate=[])

        for _ in range(3):
            g.admit(now=0)

        assert not g.admit(now=0)

    def test_releasing_frees_a_slot(self):
        g = gate(nums=1, rate=[])

        assert g.admit(now=0)
        assert not g.admit(now=0)

        g.release()
        assert g.admit(now=0)

    def test_release_does_not_go_negative(self):
        g = gate(nums=1, rate=[])

        for _ in range(5):
            g.release()

        assert g.connections == 0
        assert g.admit(now=0)

class TestConnectionRate:
    def test_admits_up_to_the_window_allowance(self):
        g = gate(rate=[(1, 3)])

        assert [g.admit(now=0) for _ in range(3)] == [True, True, True]
        assert not g.admit(now=0)

    def test_the_window_slides(self):
        g = gate(rate=[(1, 2)])

        assert g.admit(now=0.0)
        assert g.admit(now=0.1)
        assert not g.admit(now=0.2)

        # Once the first two are older than the period, the budget is free again.
        assert g.admit(now=1.5)

    def test_the_boundary_is_inclusive_of_the_period(self):
        # An entry exactly `period` old still counts as being inside the window.
        g = gate(rate=[(1, 1)])

        assert g.admit(now=0.0)
        assert not g.admit(now=1.0)
        assert g.admit(now=1.0001)

    def test_every_window_is_enforced(self):
        # With [(1, 5), (60, 6)] a burst of 5 per second is allowed, but only
        # 6 total per minute.
        g = gate(rate=[(1, 5), (60, 6)])

        assert sum(g.admit(now=0.0) for _ in range(5)) == 5
        assert not g.admit(now=0.5)   # the 1s window is full

        assert g.admit(now=2.0)       # 1s window cleared, 6th of the minute
        assert not g.admit(now=3.0)   # the 60s window is now full

    def test_a_refused_connection_is_not_recorded(self):
        # A rejected attempt must not consume budget, or the server could
        # never recover while a peer keeps retrying.
        g = gate(rate=[(10, 1)])

        assert g.admit(now=0)

        for at in range(1, 10):
            assert not g.admit(now=at)

        assert len(g.history) == 1
        assert g.admit(now=10.5)

    def test_a_refused_connection_does_not_consume_a_slot(self):
        g = gate(nums=10, rate=[(1, 1)])

        g.admit(now=0)
        g.admit(now=0)

        assert g.connections == 1

    def test_an_empty_rate_disables_rate_limiting(self):
        g = gate(rate=[])

        assert all(g.admit(now=0) for _ in range(1000))

class TestHousekeeping:
    def test_the_window_is_the_longest_period(self):
        assert gate(rate=[(1, 5), (60, 10), (5, 7)]).window == 60
        assert gate(rate=[]).window == 0

    def test_defaults_match_the_documented_limits(self):
        limits = UDSServerLimits()

        assert limits.max_connection_nums == 16384
        assert limits.max_connection_rate == [(1, 25), (5, 50), (60, 75)]
