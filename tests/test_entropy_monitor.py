from src.entropy_monitor.entropy_monitor import shannon_entropy, EntropyMonitor


def test_shannon_entropy_zero_for_uniform_data():
    assert shannon_entropy([1, 1, 1, 1]) == 0.0


def test_shannon_entropy_max_for_uniform_distribution():
    assert shannon_entropy([1, 2, 3, 4]) == 2.0


def test_shannon_entropy_empty_data():
    assert shannon_entropy([]) == 0.0


def test_baseline_not_set_before_window_fills():
    monitor = EntropyMonitor(window_size=10, threshold=0.3)
    for i in range(5):
        result = monitor.update(i % 3)
    assert result["baseline"] is None
    assert result["anomaly"] is False


def test_baseline_set_once_window_fills():
    monitor = EntropyMonitor(window_size=10, threshold=0.3)
    result = None
    for i in range(10):
        result = monitor.update(i % 3)
    assert result["baseline"] is not None


def test_no_anomaly_on_stable_data():
    monitor = EntropyMonitor(window_size=10, threshold=0.3)
    result = None
    for i in range(30):
        result = monitor.update(i % 3)
    assert result["anomaly"] is False


def test_anomaly_flagged_on_entropy_drop():
    monitor = EntropyMonitor(window_size=10, threshold=0.3)
    for i in range(10):
        monitor.update(i % 5)

    result = None
    for _ in range(10):
        result = monitor.update(0)

    assert result["anomaly"] is True
    assert result["deviation"] > 0.3