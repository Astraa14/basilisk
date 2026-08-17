"""Tests for TCP connection tracking and anomaly detection."""

from basilisk.tcp import ConnectionState, TcpProber, TcpTracker


class TestTcpTracker:
    def test_lifecycle_clean_close(self):
        tracker = TcpTracker()
        conn_id = tracker.open("example.com", 443)
        tracker.established(conn_id)
        tracker.data(conn_id, bytes_sent=10, bytes_recv=20)
        tracker.close(conn_id, clean=True)
        conn = tracker.snapshot()[0]
        assert conn.state is ConnectionState.CLOSED
        assert conn.connect_ms >= 0
        assert conn.bytes_sent == 10
        assert conn.bytes_recv == 20

    def test_unclean_close_marks_reset(self):
        tracker = TcpTracker()
        conn_id = tracker.open("example.com", 443)
        tracker.established(conn_id)
        tracker.close(conn_id, clean=False)
        assert tracker.snapshot()[0].state is ConnectionState.RESET

    def test_refused_and_timeout_states(self):
        tracker = TcpTracker()
        tracker.refused("a.com", 80)
        conn_id = tracker.open("a.com", 80)
        tracker.timeout(conn_id)
        states = {c.state for c in tracker.snapshot()}
        assert ConnectionState.REFUSED in states
        assert ConnectionState.TIMEOUT in states

    def test_no_anomalies_below_min_sample(self):
        tracker = TcpTracker()
        for _ in range(3):
            conn_id = tracker.open("x.com", 80)
            tracker.established(conn_id)
            tracker.close(conn_id, clean=True)
        stats, anomalies = tracker.report()
        assert stats["total"] == 3
        assert anomalies == []

    def test_reset_ratio_anomaly(self):
        tracker = TcpTracker()
        for _ in range(5):
            conn_id = tracker.open("x.com", 80)
            tracker.established(conn_id)
            tracker.reset(conn_id)
        _, anomalies = tracker.report()
        labels = [a["label"] for a in anomalies]
        assert "Excessive TCP resets" in labels

    def test_refusal_anomaly(self):
        tracker = TcpTracker()
        for _ in range(6):
            tracker.refused("x.com", 80)
        _, anomalies = tracker.report()
        labels = [a["label"] for a in anomalies]
        assert "Intermittent connection refusals" in labels

    def test_half_open_anomaly(self):
        tracker = TcpTracker()
        for _ in range(4):
            conn_id = tracker.open("x.com", 80)
            tracker.timeout(conn_id)
        _, anomalies = tracker.report()
        labels = [a["label"] for a in anomalies]
        assert "Half-open connections" in labels


class TestTcpProber:
    def test_probe_against_refused_port(self):
        tracker = TcpTracker()
        prober = TcpProber(tracker=tracker, timeout=0.5)
        report = prober.probe("127.0.0.1", 1, attempts=2)
        assert report["endpoint"] == "127.0.0.1:1"
        assert report["stats"]["total"] == 2
        states = set(report["stats"]["states"])
        assert states  # refused and/or timeout depending on platform