# Licensed under the Apache-2.0 license

import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend
import os

def gen_ecdsa_vector():
    private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
    public_key = private_key.public_key()

    message = os.urandom(64)  # Generate a random 64-byte message
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))
    digest = hashlib.sha384(message).digest()

    qx = public_key.public_numbers().x.to_bytes(48, 'big')
    qy = public_key.public_numbers().y.to_bytes(48, 'big')
    r, s = decode_dss_signature(signature)
    r_bytes = r.to_bytes(48, "big")
    s_bytes = s.to_bytes(48, "big")

    print("    EcdsaTestVec {")
    print(f"        qx: hex!(\"{qx.hex().upper()}\"),")
    print(f"        qy: hex!(\"{qy.hex().upper()}\"),")
    print(f"        r:  hex!(\"{r_bytes.hex().upper()}\"),")
    print(f"        s:  hex!(\"{s_bytes.hex().upper()}\"),")
    print(f"        m:  hex!(\"{digest.hex().upper()}\"),")
    print(f"        result: true,")
    print("    },")

if __name__ == "__main__":
    gen_ecdsa_vector()

