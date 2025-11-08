import argparse
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat._oid import ExtendedKeyUsageOID

def main(domains: list[str], vaild_days: int):
    # Load int cert
    with open("./int_cert.pem", "rb") as int_crtfile:
        int_cert = x509.load_pem_x509_certificate(int_crtfile.read())

    # Load int private key
    with open("./int_key.pem", "rb") as int_keyfile:
        int_key = serialization.load_pem_private_key(
            int_keyfile.read(), password=None
        )

    ee_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CFMS End Entity Organization"),
    ])
    san_list = [x509.DNSName(domain) for domain in domains]
    ee_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        int_cert.subject
    ).public_key(
        ee_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=vaild_days)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            int_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    ).sign(int_key, hashes.SHA256())

    with open("./ee_key.pem", "wb") as f:
        f.write(ee_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("./ee_cert.pem", "wb") as f:
        f.write(ee_cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate EE certificate for specified domains.")
    parser.add_argument("domains", nargs="+", help="Domain names for the certificate (e.g. example.com www.example.com)")
    parser.add_argument("-D", "--days", type=int, default=[30], nargs=1, help="The validity period of the certificate to be issued.")
    args = parser.parse_args()
    main(args.domains, args.days[0])
