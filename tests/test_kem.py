from src.crypto.kem import KEM, encapsulate


def test_kem_shared_secret_match():
    receiver = KEM()
    public_key = receiver.generate_keypair()

    ciphertext, sender_secret = encapsulate(public_key)
    receiver_secret = receiver.decapsulate(ciphertext)

    assert sender_secret == receiver_secret


def test_kem_secret_length():
    receiver = KEM()
    public_key = receiver.generate_keypair()

    ciphertext, sender_secret = encapsulate(public_key)
    receiver_secret = receiver.decapsulate(ciphertext)

    assert len(sender_secret) == 32
    assert len(receiver_secret) == 32