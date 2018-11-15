import copy
import threading


class ThreadsafeCopy:
    """
    copy methods are throwing thread safe exceptions since
    """
    @staticmethod
    def copy(obj):
        lock = threading.Lock()
        with lock:
            return copy.copy(obj)

    @staticmethod
    def deepcopy(obj):
        lock = threading.Lock()
        with lock:
            return copy.deepcopy(obj)

