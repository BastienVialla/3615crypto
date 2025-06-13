import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding as asym_padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from kyber_py.kyber import Kyber512, Kyber768, Kyber1024
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import time

def encrypt_ecc(message: str, curve_name: str = "SECP 256 R1") -> dict:
    """
    Encrypt a message using ECC + AES hybrid encryption.
    Returns ECC key components and AES encrypted data.

    Args:
        message (str): The plaintext message.
        curve_name (str): ECC curve name. Supported: SECP256R1, SECP384R1, SECP521R1

    Returns:
        dict: {
            'ciphertext': bytes,
            'shared_key': bytes,
            'private_key_pem': bytes,
            'public_key_pem': bytes,
            'private_components': dict,
            'public_components': dict
        }
    """
    curve_map = {
        "SECP 256 R1": ec.SECP256R1(),
        "SECP 384 R1": ec.SECP384R1(),
        "SECP 512 R1": ec.SECP521R1(),
    }

    if curve_name not in curve_map:
        raise ValueError(f"Unsupported curve: {curve_name}")

    curve = curve_map[curve_name]

    # Generate ECC keys
    start_time = time.perf_counter()
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    end_time = time.perf_counter()
    keygen_time = end_time - start_time


    # Hybrid encryption (AES)
    aes_key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    start_time = time.perf_counter()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    end_time = time.perf_counter()
    encrypt_time = end_time - start_time
    
    
    return keygen_time, encrypt_time

def kyber_encrypt(
    message: str,
    key_param: str
):
    """
    Hybrid encrypt a UTF-8 `message` with:
      - AES-GCM (128/192/256 bits)
      - Kyber KEM (Kyber512/768/1024)

    """
    # 1. Encode the input string as UTF-8 bytes
    message_bytes = message.encode('utf-8')

    # 1. Encode the input string as UTF-8 bytes
    message_bytes = message.encode('utf-8')

    if key_param == 'ML-KEM-512':
        Kem = Kyber512
        aes_key_size = 128
    elif key_param == 'ML-KEM-768':
        Kem = Kyber768
        aes_key_size = 192
    elif key_param == 'ML-KEM-1024':
        Kem = Kyber1024
        aes_key_size = 256
    
    # 3. Generate Kyber keypair and encapsulate
    start_time = time.perf_counter()
    pk, sk = Kem.keygen()
    end_time = time.perf_counter()
    keygen_time = end_time-start_time
    start_time = time.perf_counter()
    shared_secret, kem_ciphertext = Kem.encaps(pk)
    end_time = time.perf_counter()
    encrypt_time = end_time-start_time

    # 4. Truncate the shared secret to derive the AES key
    aes_key = shared_secret[: aes_key_size // 8]

    # 5. AES-GCM encryption
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, message_bytes, None)

    # 6. Return combined ciphertext and keys
    return keygen_time, encrypt_time

def encrypt_rsa(message: str, key_size: int = 2048) -> tuple[bytes, dict, dict]:
    """
    Encrypts a string message using RSA.

    Generates a new RSA key pair (public and private) for each call.
    Encrypts the message using the public key with OAEP padding (recommended).

    Args:
        message: The string message to encrypt.
        key_size: The desired RSA key size in bits (e.g., 2048, 3072, 4096).
                  Defaults to 2048. Must be at least 2048 for security.

    Returns:
        A tuple containing:
        - ciphertext (bytes): The encrypted data.
        - keys (dict): A dictionary containing the PEM-encoded public and
                       private keys as strings:
                       {'public_key': str, 'private_key': str}
        - components (dict): A dictionary containing two sub-dictionaries,
                             'public_key' and 'private_key', holding the
                             integer components of the respective keys.
                             'n' and 'e' are included in both for completeness.
                             {'public_key': {'n': int, 'e': int},
                              'private_key': {'p': int, 'q': int, 'd': int,
                                              'n': int, 'e': int, 'dmp1': int,
                                              'dmq1': int, 'iqmp': int}}

    Raises:
        ValueError: If key_size is less than 2048, or if the message is too
                    long to be encrypted with the chosen key size and padding.
    """
    # if key_size < 2048:
    #     raise ValueError("Key size must be at least 2048 bits for RSA security.")

    #private_key_path = RSA_CACHE_DIRECTORY / f"rsa_private_key_{key_size}.pem"
    #public_key_path = RSA_CACHE_DIRECTORY / f"rsa_public_key_{key_size}.pem"

    private_key = None
    public_key = None
    
    if private_key is None and public_key is None:
        # --- Key Generation ---
        start_time = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537, # Standard public exponent
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        end_time = time.perf_counter()
        keygen_time = end_time - start_time

    # --- Prepare Plaintext ---
    plaintext = message.encode('utf-8')

    # --- Check Message Length ---
    # OAEP padding adds overhead. The maximum message length depends on the
    # key size and the hash algorithm used (SHA256 here).
    # Max length = key_size_bytes - 2 * hash_output_size_bytes - 2
    sha256_hash_len = hashes.SHA256.digest_size # Usually 32 bytes
    max_len = (key_size // 8) - (2 * sha256_hash_len) - 2
    if len(plaintext) > max_len:
        raise ValueError(
            f"Message is too long ({len(plaintext)} bytes) for RSA key size "
            f"{key_size} bits with OAEP padding. Maximum length is {max_len} bytes."
        )

    # --- Encryption ---
    start_time = time.perf_counter()
    ciphertext = public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    end_time = time.perf_counter()
    encrypt_time = end_time - start_time

    # # --- Serialize Keys to PEM Format ---
    # private_pem = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # )

    # public_pem = public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    
    # if key_size > 4096:
    #     try:
    #         with open(private_key_path, "wb") as key_file:
    #             key_file.write(private_pem)
    #         with open(public_key_path, "wb") as key_file:
    #             key_file.write(public_pem)
    #         print(f"Keys saved to {RSA_CACHE_DIRECTORY}.")
    #     except IOError as e:
    #         print(f"Warning: Could not save keys to {RSA_CACHE_DIRECTORY}: {e}")

    # keys_dict = {
    #     'cle secrete': private_pem.decode('utf-8'),
    #     'cle publique': public_pem.decode('utf-8')
    # }

    # # --- Extract Key Components (Structured) ---
    # private_numbers = private_key.private_numbers()
    # public_numbers = private_key.public_key().public_numbers() # Get public numbers directly

    return keygen_time, encrypt_time

def encrypt_chacha20(message: str, key_size: int = 256, key: bytes = None) -> tuple[bytes, dict]:
    """
    Encrypts a string message using ChaCha20-Poly1305.

    Generates a new 32-byte key if one is not provided.
    Note: ChaCha20-Poly1305 (IETF variant) uses a fixed 32-byte key size.
    The 'key_size' parameter is included for signature consistency with AES,
    but it must be 256 (bits) if a new key is being generated.
    Uses a unique random 12-byte (96-bit) nonce for each encryption
    (IETF variant). The nonce is prepended to the resulting ciphertext.
    The authentication tag generated by Poly1305 is appended automatically
    by the library.

    Args:
        message: The string message to encrypt.
        key_size: The desired key size in bits. For ChaCha20-Poly1305,
                  this should be 256. Defaults to 256. This is used only
                  when generating a new key (i.e., when 'key' is None).
        key: An optional pre-existing secret key (bytes). If provided,
             its length must be 32 bytes. If None, a new 32-byte key
             is generated.

    Returns:
        A tuple containing:
        - ciphertext (bytes): The encrypted data, consisting of the 12-byte nonce
                              prepended to the ciphertext and authentication tag.
        - key (bytes): The secret key used for encryption (either the
                       provided one or the newly generated one).

    Raises:
        ValueError: If key_size is invalid when generating a key, or if a
                    provided key has an incorrect length (not 32 bytes).
        TypeError: If the provided key is not bytes.
        Invalidkey: If the provided key is invalid for ChaCha20Poly1305 (e.g., all zeros).
    """
    # ChaCha20-Poly1305 uses a fixed 32-byte key size (256 bits).
    CHACHA20_KEY_BYTES_LEN = 32
    STANDARD_KEY_SIZE_BITS = 256
    # The standard IETF variant uses a 12-byte nonce.
    CHACHA20_NONCE_SIZE = 12

    if key is None:
        # --- Key Generation ---
        # Validate key_size if generating a new key
        if key_size != STANDARD_KEY_SIZE_BITS:
            # Decide whether to raise an error or a warning.
            # Raising an error is safer to prevent misuse with incorrect assumptions
            # about key size support.
            raise ValueError(f"Invalid key size for ChaCha20-Poly1305 key generation. Must be {STANDARD_KEY_SIZE_BITS} bits.")
        start_time = time.perf_counter()
        key = os.urandom(CHACHA20_KEY_BYTES_LEN)
        end_time = time.perf_counter()
        keygen_time = end_time - start_time
        # Use a cryptographically secure random number generator for the key
    else:
        # --- Key Validation ---
        if not isinstance(key, bytes):
             raise TypeError("Provided key must be of type bytes.")
        if len(key) != CHACHA20_KEY_BYTES_LEN:
             raise ValueError(f"Invalid provided key length: {len(key)} bytes. Must be {CHACHA20_KEY_BYTES_LEN} bytes for ChaCha20-Poly1305.")
        # If a key is provided, we can optionally warn if key_size was also provided
        # and doesn't match 256, but since the provided key's length is the authority,
        # we prioritize its length validation. For simplicity, we'll just use the
        # provided key directly after validating its length.

    # --- Prepare Plaintext ---
    # ChaCha20-Poly1305 works on bytes, so encode the string message (UTF-8 is common)
    plaintext = message.encode('utf-8')

    # --- Generate Nonce ---
    # ChaCha20-Poly1305 requires a unique nonce for every encryption operation
    # with the same key. The IETF variant uses a 12-byte nonce.
    # It does NOT need to be secret, just unique. We will prepend it to the ciphertext.
    nonce = os.urandom(CHACHA20_NONCE_SIZE)

    # --- Encryption ---
    # Use ChaCha20Poly1305 for authenticated encryption
    try:
        chacha20 = ChaCha20Poly1305(key)
        # Encrypt the plaintext. ChaCha20Poly1305 handles the authentication tag,
        # which it appends to the ciphertext.
        # We pass 'None' for associated data as we are not using it here.
        start_time = time.perf_counter()
        ciphertext_and_tag = chacha20.encrypt(nonce, plaintext, None)
        end_time = time.perf_counter()
        encrypt_time = end_time - start_time
        start_time = time.perf_counter()
        ciphertext_and_tag = chacha20.decrypt(nonce, ciphertext_and_tag, None)
        end_time = time.perf_counter()
        decrypt_time = end_time - start_time
    except InvalidKey:
         raise InvalidKey("The provided key is invalid for ChaCha20Poly1305.")
    except Exception as e:
        # Catch other potential errors during encryption
        print(f"An error occurred during encryption: {e}")
        raise # Re-raise the exception

    return keygen_time, encrypt_time, decrypt_time

def encrypt_aes(message: str, key_size: int = 256, key: bytes = None) -> tuple[bytes, dict]:
    if key is None:
        # --- Key Generation ---
        if key_size not in [128, 192, 256]:
            raise ValueError("Invalid key size. Must be 128, 192, or 256 bits when generating a key.")
        key_bytes_len = key_size // 8
        # Use a cryptographically secure random number generator
        start_time = time.perf_counter()
        key = os.urandom(key_bytes_len)
        end_time = time.perf_counter()
        keygen_time = end_time - start_time
    else:
        # --- Key Validation ---
        if not isinstance(key, bytes):
             raise TypeError("Provided key must be of type bytes.")
        key_bytes_len = len(key)
        if key_bytes_len not in [16, 24, 32]: # Corresponds to 128, 192, 256 bits
             raise ValueError(f"Invalid provided key length: {key_bytes_len} bytes. Must be 16, 24, or 32 bytes.")
        # Optional: Warn or error if key_size was explicitly passed and doesn't match len(key)
        # For simplicity here, we just use the length of the provided key.

    # --- Prepare Plaintext ---
    # AES works on bytes, so encode the string message (UTF-8 is common)
    plaintext = message.encode('utf-8')

    # --- Generate Nonce ---
    # GCM requires a unique nonce for every encryption operation with the same key.
    # 12 bytes (96 bits) is recommended by NIST and is efficient.
    # It does NOT need to be secret, just unique. We will prepend it to the ciphertext.
    nonce = os.urandom(12)

    # --- Encryption ---
    # Use AESGCM for authenticated encryption
    try:
        aesgcm = AESGCM(key)
        start_time = time.perf_counter()
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
        end_time = time.perf_counter()
        encrypt_time = end_time - start_time
        start_time = time.perf_counter()
        ciphertext_and_tag = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
        end_time = time.perf_counter()
        decrypt_time = end_time - start_time
    except Exception as e:
        # Catch potential errors during encryption (though less likely with validated key)
        print(f"An error occurred during encryption: {e}")
        raise # Re-raise the exception

    
    # --- Combine Nonce and Ciphertext ---
    # Prepend the nonce to the ciphertext+tag. The recipient will need the nonce
    # (which they can extract from the start of the received data) to decrypt.
    full_ciphertext = ciphertext_and_tag

    return keygen_time, encrypt_time, decrypt_time

gkWh = 32
TDP_W = 12
def get_consumption(time_us):
    time_s = time_us/1_000_000
    kWh = time_s*TDP_W/(1000*3600)
    return time_s*TDP_W, kWh*gkWh

N = 1_000_000
message = b"Coucou"
start_time = time.perf_counter()
for _ in range(N):
    hash = hashlib.sha256(message).digest()    
end_time = time.perf_counter()

execution_time_seconds = end_time - start_time
execution_time_ms = execution_time_seconds * 1_000_000
execution_time_ms /= N
print(f"SHA256 executed in {execution_time_ms:.6f} us")
W, g = get_consumption(execution_time_ms)
print(f"SHA256 {W} W, {g} gCO2")


start_time = time.perf_counter()
for _ in range(N):
    hash = hashlib.sha384(message).digest()    
end_time = time.perf_counter()

execution_time_seconds = end_time - start_time
execution_time_ms = execution_time_seconds * 1_000_000
execution_time_ms /= N
print(f"SHA384 executed in {execution_time_ms:.6f} us")
W, g = get_consumption(execution_time_ms)
print(f"SHA384 {W} W, {g} gCO2")

start_time = time.perf_counter()
for _ in range(N):
    hash = hashlib.sha512(message).digest()    
end_time = time.perf_counter()

execution_time_seconds = end_time - start_time
execution_time_ms = execution_time_seconds * 1_000_000
execution_time_ms /= N
print(f"SHA512 executed in {execution_time_ms:.6f} us")
W, g = get_consumption(execution_time_ms)
print(f"SHA512 {W} W, {g} gCO2")

start_time = time.perf_counter()
for _ in range(N):
    hash = hashlib.sha3_256(message).digest()    
end_time = time.perf_counter()

execution_time_seconds = end_time - start_time
execution_time_ms = execution_time_seconds * 1_000_000
execution_time_ms /= N
print(f"SHA3 256 executed in {execution_time_ms:.6f} us")
W, g = get_consumption(execution_time_ms)
print(f"SHA3 256 {W} W, {g} gCO2")

start_time = time.perf_counter()
for _ in range(N):
    hash = hashlib.sha3_384(message).digest()    
end_time = time.perf_counter()

execution_time_seconds = end_time - start_time
execution_time_ms = execution_time_seconds * 1_000_000
execution_time_ms /= N
print(f"SHA3 384 executed in {execution_time_ms:.6f} us")
W, g = get_consumption(execution_time_ms)
print(f"SHA3 384 {W} W, {g} gCO2")

start_time = time.perf_counter()
for _ in range(N):
    hash = hashlib.sha3_512(message).digest()    
end_time = time.perf_counter()

execution_time_seconds = end_time - start_time
execution_time_ms = execution_time_seconds * 1_000_000
execution_time_ms /= N
print(f"SHA3 512 executed in {execution_time_ms:.6f} us")
W, g = get_consumption(execution_time_ms)
print(f"SHA3 512 {W} W, {g} gCO2")

print('\n')
message = "Coucou"
for k in [128, 192, 256]:
    keygen_time = 0
    encrypt_time = 0
    decrypt_time = 0
    for _ in range(N):
        kt, et, dt = encrypt_aes(message, k)
        keygen_time += kt
        encrypt_time += et
        decrypt_time += dt
    keygen_time *= 1_000_000
    encrypt_time *= 1_000_000
    decrypt_time *= 1_000_000
    keygen_time /= N
    encrypt_time /= N
    decrypt_time /= N
    print(f"AES {k} keygen {keygen_time} us")
    print(f"AES {k} encrypt {encrypt_time} us")
    print(f"AES {k} decrypt {decrypt_time} us")
    W, g = get_consumption(keygen_time)
    print(f"keygen {W} W, {g} gCO2")
    W, g = get_consumption(encrypt_time)
    print(f"encrypt {W} W, {g} gCO2")
    W, g = get_consumption(decrypt_time)
    print(f"decrypt {W} W, {g} gCO2")

print('\n')
message = "Coucou"
for k in [256]:
    keygen_time = 0
    encrypt_time = 0
    decrypt_time = 0
    for _ in range(N):
        kt, et, dt = encrypt_chacha20(message, k)
        keygen_time += kt
        encrypt_time += et
        decrypt_time += dt
    keygen_time *= 1_000_000
    encrypt_time *= 1_000_000
    decrypt_time *= 1_000_000
    keygen_time /= N
    encrypt_time /= N
    decrypt_time /= N
    print(f"ChaCha {k} keygen {keygen_time} us")
    print(f"ChaCha {k} encrypt {encrypt_time} us")
    print(f"ChaCha {k} decrypt {decrypt_time} us")
    W, g = get_consumption(keygen_time)
    print(f"keygen {W} W, {g} gCO2")
    W, g = get_consumption(encrypt_time)
    print(f"encrypt {W} W, {g} gCO2")
    W, g = get_consumption(decrypt_time)
    print(f"decrypt {W} W, {g} gCO2")

print('\n')    
N = 10
for k in [1024, 2048, 3072, 7680, 15360]:
    keygen_time = 0
    encrypt_time = 0
    if k > 3072:
        N = 1
    for _ in range(N):
        kt, et= encrypt_rsa(message, k)
        keygen_time += kt
        encrypt_time += et
    keygen_time *= 1_000_000
    encrypt_time *= 1_000_000
    keygen_time /= N
    encrypt_time /= N
    print(f"RSA {k} keygen {keygen_time} us")
    print(f"RSA {k} encrypt {encrypt_time} us")
    W, g = get_consumption(keygen_time)
    print(f"keygen {W} W, {g} gCO2")
    W, g = get_consumption(encrypt_time)
    print(f"encrypt {W} W, {g} gCO2")

print('\n')
N = 100
for k in ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']:
    keygen_time = 0
    encrypt_time = 0
    for _ in range(N):
        kt, et= kyber_encrypt(message, k)
        keygen_time += kt
        encrypt_time += et
    keygen_time *= 1_000_000
    encrypt_time *= 1_000_000
    keygen_time /= N*10
    encrypt_time /= N*10
    print(f"kyber {k} keygen {keygen_time} us")
    print(f"kyber {k} encrypt {encrypt_time} us")
    W, g = get_consumption(keygen_time)
    print(f"keygen {W} W, {g} gCO2")
    W, g = get_consumption(encrypt_time)
    print(f"encrypt {W} W, {g} gCO2")
    
print('\n')
N = 100
for k in ['SECP 256 R1', 'SECP 384 R1', 'SECP 512 R1']:
    keygen_time = 0
    encrypt_time = 0
    for _ in range(N):
        kt, et= encrypt_ecc(message, k)
        keygen_time += kt
        encrypt_time += et
    keygen_time *= 1_000_000
    encrypt_time *= 1_000_000
    keygen_time /= N
    encrypt_time /= N
    print(f"ECC {k} keygen {keygen_time} us")
    print(f"ECC {k} encrypt {encrypt_time} us")
    W, g = get_consumption(keygen_time)
    print(f"keygen {W} W, {g} gCO2")
    W, g = get_consumption(encrypt_time)
    print(f"encrypt {W} W, {g} gCO2")