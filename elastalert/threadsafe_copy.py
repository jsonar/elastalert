import copy
import threading


class ThreadsafeCopy:
    copy_lock = threading.Lock()
    deepcopy_lock = threading.Lock()

    """
    copy methods are throwing thread safe exceptions since
    """
    @staticmethod
    def copy(obj):
        with ThreadsafeCopy.copy_lock:
            return copy.copy(obj)

    @staticmethod
    def deepcopy(obj):
        with ThreadsafeCopy.deepcopy_lock:
            return copy.deepcopy(obj)

