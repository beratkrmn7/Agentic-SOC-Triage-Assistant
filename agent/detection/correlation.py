from typing import List, Callable, Dict, Any, TypeVar, Tuple
from collections import deque
from datetime import timedelta
from agent.schema import CanonicalLogEvent

T = TypeVar('T')

def sliding_window_scan(
    events: List[CanonicalLogEvent],
    window_seconds: int,
    condition_fn: Callable[[deque[CanonicalLogEvent]], Tuple[bool, Dict[str, Any]]]
) -> List[Tuple[List[CanonicalLogEvent], Dict[str, Any]]]:
    """
    O(N) sliding window across a chronologically sorted list of events.
    condition_fn takes a deque of events currently in the window, and returns
    a tuple (is_match, context_dict). If matched, the window is yielded and we clear it
    to avoid overlapping redundant matches for the exact same pattern.
    """
    results = []
    window = deque()
    
    for event in events:
        window.append(event)
        
        # Remove events outside the window
        while window and (event.timestamp - window[0].timestamp).total_seconds() > window_seconds:
            window.popleft()
            
        is_match, context = condition_fn(window)
        if is_match:
            # We found a match. To prevent massive duplicate signals, we record it,
            # and depending on the detector, we might want to clear the window.
            # For simplicity, we yield a copy of the window and clear.
            results.append((list(window), context))
            window.clear()
            
    return results
