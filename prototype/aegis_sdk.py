import requests
import os
import threading
from contextlib import contextmanager

class Aegis:
    def __init__(self, control_plane_url="http://localhost:5000"):
        self.control_plane_url = control_plane_url
        self.active_policies = {}

    @contextmanager
    def enforce(self, policy_name: str):
        """
        Context manager that dynamically registers the current thread's PID
        with the Aegis Control Plane under a specific security policy.
        """
        pid = os.getpid()
        tid = threading.get_native_id()
        
        print(f"[Aegis SDK] 🔒 Locking Thread {tid} into policy '{policy_name}'...")
        
        try:
            # Tell the kernel/control plane to start enforcing
            requests.post(f"{self.control_plane_url}/api/v1/enforce", json={
                "pid": pid,
                "tid": tid,
                "policy": policy_name,
                "action": "attach"
            })
            yield
        finally:
            print(f"[Aegis SDK] 🔓 Releasing Thread {tid} from policy '{policy_name}'.")
            requests.post(f"{self.control_plane_url}/api/v1/enforce", json={
                "pid": pid,
                "tid": tid,
                "policy": policy_name,
                "action": "detach"
            })

# Global instance for easy importing
aegis = Aegis()
