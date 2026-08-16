import oqs


class KEM:
    def __init__(self, algorithm: str = "ML-KEM-768"):
        self.algorithm = algorithm
        self.kem = None
        self.public_key = None

    def generate_keypair(self):
        self.kem = oqs.KeyEncapsulation(self.algorithm)
        self.public_key = self.kem.generate_keypair()
        return self.public_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if self.kem is None:
            raise ValueError("Keypair not generated yet")
        return self.kem.decap_secret(ciphertext)


def encapsulate(public_key: bytes, algorithm: str = "ML-KEM-768"):
    with oqs.KeyEncapsulation(algorithm) as sender_kem:
        ciphertext, shared_secret = sender_kem.encap_secret(public_key)
        return ciphertext, shared_secret