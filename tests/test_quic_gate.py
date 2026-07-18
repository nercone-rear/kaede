import pytest

from kaede.quic.api.server import QUICGate, QUICServerLimits

# QUICGate is admission control for peers rather than for connections: a global
# cap on how many peers are being served at once, and a per-peer sliding-window
# cap on how often a new one may appear. The clock is injected so the windows can
# be checked exactly rather than by sleeping.

def gate(nums=1000, rate=None):
    limits = QUICServerLimits()
    limits.max_connection_nums = nums

    if rate is not None:
        limits.max_connection_rate = rate

    return QUICGate(limits)

class TestConnectionCount:
    def test_admits_up_to_the_limit(self):
        g = gate(nums=3, rate=[])

        assert [g.admit("10.0.0.1", now=0) for _ in range(3)] == [True, True, True]

    def test_refuses_beyond_the_limit(self):
        g = gate(nums=3, rate=[])

        for _ in range(3):
            g.admit("10.0.0.1", now=0)

        assert not g.admit("10.0.0.1", now=0)

    def test_releasing_frees_a_slot(self):
        g = gate(nums=1, rate=[])

        assert g.admit("10.0.0.1", now=0)
        assert not g.admit("10.0.0.2", now=0)

        g.release()
        assert g.admit("10.0.0.2", now=0)

    def test_release_does_not_go_negative(self):
        g = gate(nums=1, rate=[])

        for _ in range(5):
            g.release()

        assert g.connections == 0
        assert g.admit("10.0.0.1", now=0)

    def test_the_count_is_shared_across_peers(self):
        g = gate(nums=2, rate=[])

        assert g.admit("10.0.0.1", now=0)
        assert g.admit("10.0.0.2", now=0)
        assert not g.admit("10.0.0.3", now=0)

class TestConnectionRate:
    def test_admits_up_to_the_window_allowance(self):
        g = gate(rate=[(1, 3)])

        assert [g.admit("10.0.0.1", now=0) for _ in range(3)] == [True, True, True]
        assert not g.admit("10.0.0.1", now=0)

    def test_the_window_slides(self):
        g = gate(rate=[(1, 2)])

        assert g.admit("10.0.0.1", now=0.0)
        assert g.admit("10.0.0.1", now=0.1)
        assert not g.admit("10.0.0.1", now=0.2)

        assert g.admit("10.0.0.1", now=1.5)

    def test_the_boundary_is_inclusive_of_the_period(self):
        g = gate(rate=[(1, 1)])

        assert g.admit("10.0.0.1", now=0.0)
        assert not g.admit("10.0.0.1", now=1.0)
        assert g.admit("10.0.0.1", now=1.0001)

    def test_every_window_is_enforced(self):
        g = gate(rate=[(1, 5), (60, 6)])

        assert sum(g.admit("10.0.0.1", now=0.0) for _ in range(5)) == 5
        assert not g.admit("10.0.0.1", now=0.5)   # the 1s window is full

        assert g.admit("10.0.0.1", now=2.0)       # 1s window cleared, 6th of the minute
        assert not g.admit("10.0.0.1", now=3.0)   # the 60s window is now full

    def test_peers_are_counted_separately(self):
        # RFC 9000 section 8.1 has a server validate an address with Retry
        # precisely because a datagram's source is trivially forged, so this
        # only limits the honest case. It must still not let one address spend
        # another's budget.
        g = gate(rate=[(1, 1)])

        assert g.admit("10.0.0.1", now=0)
        assert not g.admit("10.0.0.1", now=0)
        assert g.admit("10.0.0.2", now=0)

    def test_a_refused_peer_is_not_recorded(self):
        g = gate(rate=[(10, 1)])

        assert g.admit("10.0.0.1", now=0)

        for at in range(1, 10):
            assert not g.admit("10.0.0.1", now=at)

        assert len(g.history["10.0.0.1"]) == 1
        assert g.admit("10.0.0.1", now=10.5)

    def test_a_refused_peer_does_not_consume_a_slot(self):
        g = gate(nums=10, rate=[(1, 1)])

        g.admit("10.0.0.1", now=0)
        g.admit("10.0.0.1", now=0)

        assert g.connections == 1

    def test_an_empty_rate_disables_rate_limiting(self):
        g = gate(rate=[])

        assert all(g.admit("10.0.0.1", now=0) for _ in range(1000))

class TestHousekeeping:
    def test_sweep_forgets_idle_peers(self):
        g = gate(rate=[(1, 5)])

        g.admit("10.0.0.1", now=0)
        assert "10.0.0.1" in g.history

        g.sweep(now=100)
        assert g.history == {}

    def test_sweep_keeps_active_peers(self):
        g = gate(rate=[(60, 5)])

        g.admit("10.0.0.1", now=0)
        g.sweep(now=10)

        assert "10.0.0.1" in g.history

    def test_the_window_is_the_longest_period(self):
        assert gate(rate=[(1, 5), (60, 10), (5, 7)]).window == 60
        assert gate(rate=[]).window == 0

    def test_defaults_match_the_documented_limits(self):
        limits = QUICServerLimits()

        assert limits.max_connection_nums == 16384
        assert limits.max_connection_rate == [(1, 25), (5, 50), (60, 75)]

    def test_the_stream_limit_is_carried_alongside(self):
        # RFC 9000 section 4.6 caps concurrent streams per connection, which is
        # a QUIC concern the other protocols' limits have no counterpart for.
        assert QUICServerLimits().max_stream_nums == 100

    def test_limits_are_not_shared_between_instances(self):
        first, second = QUICServerLimits(), QUICServerLimits()
        first.max_connection_rate.append((3600, 1000))

        assert second.max_connection_rate != first.max_connection_rate
