"""AES-CTR adapter using Android's crypto provider; upstream API is preserved."""
try:
    from java import jclass
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
else:
    _JavaCipher = jclass("javax.crypto.Cipher")
    _SecretKeySpec = jclass("javax.crypto.spec.SecretKeySpec")
    _IvParameterSpec = jclass("javax.crypto.spec.IvParameterSpec")

    class algorithms:
        class AES:
            def __init__(self, key):
                if len(key) not in (16, 24, 32):
                    raise ValueError("Invalid AES key length")
                self.key = bytes(key)

    class modes:
        class CTR:
            def __init__(self, iv):
                if len(iv) != 16:
                    raise ValueError("Invalid AES IV length")
                self.iv = bytes(iv)

    class _Stream:
        def __init__(self, key, iv):
            self.cipher = _JavaCipher.getInstance("AES/CTR/NoPadding")
            self.cipher.init(_JavaCipher.ENCRYPT_MODE,
                             _SecretKeySpec(key, "AES"), _IvParameterSpec(iv))

        def update(self, data):
            if not data:
                return b""
            result = self.cipher.update(bytes(data))
            # Chaquopy exposes Java byte[] through the buffer protocol. Bulk copy
            # avoids one JNI/Python conversion per byte on Telegram media streams.
            return memoryview(result).tobytes() if result is not None else b""

    class Cipher:
        def __init__(self, algorithm, mode):
            self.key, self.iv = algorithm.key, mode.iv

        def encryptor(self):
            return _Stream(self.key, self.iv)

        decryptor = encryptor
