from agent.detection.scoring import calculate_signal_confidence

def test_confidence_scoring():
    c = calculate_signal_confidence(10, 5, base_confidence=0.5, max_confidence=0.9)
    assert 0.5 < c <= 0.9