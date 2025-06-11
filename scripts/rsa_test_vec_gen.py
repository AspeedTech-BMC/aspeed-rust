from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from textwrap import wrap
import hashlib
import os

def format_hex_array(data: bytes) -> str:
    lines = wrap(data.hex(), 64)
    return '\n'.join('"' + line + '"' for line in lines)

def rust_hex(label: str, data: bytes, indent: int = 16) -> str:
    from textwrap import wrap

    hex_lines = wrap(data.hex(), 64)
    hex_body = '\n'.join(" " * indent + f'"{line}"' for line in hex_lines)
    return f"{label}: &hex!(\n{hex_body}\n{' ' * 8}),"

def get_hash_algorithm(name: str):
    if name == "sha256":
        return hashes.SHA256(), hashlib.sha256
    elif name == "sha384":
        return hashes.SHA384(), hashlib.sha384
    elif name == "sha512":
        return hashes.SHA512(), hashlib.sha512
    else:
        raise ValueError("Unsupported hash algorithm")

def gen_rsa_testvec(key_size: int, hash_name: str) -> str:
    hash_algo, hashlib_fn = get_hash_algorithm(hash_name)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    private_numbers = key.private_numbers()
    public_numbers = private_numbers.public_numbers

    modulus_len = key_size // 8
    n = public_numbers.n.to_bytes(modulus_len, byteorder='big')
    e = public_numbers.e.to_bytes(3, byteorder='big')
    d = private_numbers.d.to_bytes(modulus_len, byteorder='big')

    message = os.urandom(64)
    message_digest = hashlib_fn(message).digest()

    digest = hashes.Hash(hash_algo, backend=default_backend())
    digest.update(message_digest)
    digest_value = digest.finalize()

    signature = key.sign(
        message_digest,
        padding.PKCS1v15(),
        hash_algo
    )

    lines = []
    lines.append(f"    // RSA-{key_size} with {hash_name.upper()}")
    lines.append("    RsaTestVec {")
    lines.append("        k: RsaKey {")
    lines.append("            " + rust_hex('m', n))
    lines.append("            " + rust_hex('d', d))
    lines.append("            " + rust_hex('e', e))
    lines.append(f"            m_bits: {key_size},")
    lines.append(f"            d_bits: {key_size},")
    lines.append(f"            e_bits: {len(e) * 8},")
    lines.append("        },")
    lines.append("        " + rust_hex('digest', digest_value))
    lines.append("        " + rust_hex('signature', signature))
    lines.append(f"        s_size: {len(signature)},")
    lines.append(f"        d_size: {len(digest_value)},")
    lines.append("    },")
    return "\n".join(lines)

def main():
    print("""use hex_literal::hex;

pub struct RsaKey {
    pub m: &'static [u8],
    pub d: &'static [u8],
    pub e: &'static [u8],
    pub m_bits: usize,
    pub d_bits: usize,
    pub e_bits: usize,
}

pub struct RsaTestVec {
    pub k: RsaKey,
    pub digest: &'static [u8],
    pub signature: &'static [u8],
    pub s_size: usize,
    pub d_size: usize,
}""")

    print()
    print("pub static RSA_VERIFY_TV: &[RsaTestVec] = &[")
    for key_size in [2048, 3072, 4096]:
        for hash_name in ["sha256", "sha384", "sha512"]:
            print(gen_rsa_testvec(key_size, hash_name))
    print("];")

if __name__ == "__main__":
    main()

