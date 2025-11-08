import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography import x509

def pem_to_der(pem_path):
    with open(pem_path, "rb") as pem_file:
        cert = x509.load_pem_x509_certificate(pem_file.read())
    der_path = os.path.splitext(pem_path)[0] + ".der"
    with open(der_path, "wb") as der_file:
        der_file.write(cert.public_bytes(serialization.Encoding.DER))
    print(f"DER file saved to: {der_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {os.path.basename(__file__)} <pem_file_path>")
        sys.exit(1)
    pem_to_der(sys.argv[1])