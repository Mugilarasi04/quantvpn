from src.crypto.kem import KEM, encapsulate


class KeyRotationResponder:
    def __init__(self):
        self.rotation_count = 0
        self.current_secret = None

    def respond(self, anomaly_result: dict, peer_public_key: bytes):
        self.rotation_count += 1
        ciphertext, new_secret = encapsulate(peer_public_key)
        self.current_secret = new_secret
        print(f"[SECURITY] Anomaly detected (deviation={anomaly_result['deviation']:.3f}) "
              f"— rotating session key (rotation #{self.rotation_count})")
        return ciphertext, new_secret