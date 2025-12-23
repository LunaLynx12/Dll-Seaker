"""
Performance Profiler - Profile analysis operations
"""

import time
import functools
from typing import Dict, List, Any, Callable
from collections import defaultdict


class PerformanceProfiler:
    """Profile performance of analysis operations"""
    
    def __init__(self, enabled: bool = True):
        """Initialize profiler"""
        self.enabled = enabled
        self.timings = defaultdict(list)
        self.call_counts = defaultdict(int)
    
    def profile(self, operation_name: str = None):
        """Decorator to profile a function"""
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                name = operation_name or func.__name__
                start = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    elapsed = time.perf_counter() - start
                    self.timings[name].append(elapsed)
                    self.call_counts[name] += 1
            return wrapper
        return decorator
    
    def time_operation(self, operation_name: str):
        """Context manager for timing operations"""
        return TimingContext(self, operation_name)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics"""
        stats = {}
        
        for name, timings in self.timings.items():
            if timings:
                stats[name] = {
                    'count': self.call_counts[name],
                    'total_time': sum(timings),
                    'average_time': sum(timings) / len(timings),
                    'min_time': min(timings),
                    'max_time': max(timings),
                    'total_calls': len(timings)
                }
        
        total_time = sum(s['total_time'] for s in stats.values())
        
        return {
            'operations': stats,
            'total_time': total_time,
            'operation_count': len(stats),
            'enabled': self.enabled
        }
    
    def reset(self):
        """Reset all timings"""
        self.timings.clear()
        self.call_counts.clear()
    
    def get_slowest_operations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get slowest operations"""
        stats = self.get_statistics()
        operations = stats.get('operations', {})
        
        sorted_ops = sorted(
            operations.items(),
            key=lambda x: x[1]['total_time'],
            reverse=True
        )[:limit]
        
        return [
            {'name': name, **data}
            for name, data in sorted_ops
        ]


class TimingContext:
    """Context manager for timing operations"""
    
    def __init__(self, profiler: PerformanceProfiler, operation_name: str):
        self.profiler = profiler
        self.operation_name = operation_name
        self.start_time = None
    
    def __enter__(self):
        if self.profiler.enabled:
            self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.profiler.enabled and self.start_time:
            elapsed = time.perf_counter() - self.start_time
            self.profiler.timings[self.operation_name].append(elapsed)
            self.profiler.call_counts[self.operation_name] += 1
        return False

