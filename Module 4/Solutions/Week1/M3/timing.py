import time

class Timer():
    def __init__(self):
        self.start = time.perf_counter_ns()

    def tic(self):
        self.start = time.perf_counter_ns()

    def toc(self) -> int:
        return time.perf_counter_ns() - self.start