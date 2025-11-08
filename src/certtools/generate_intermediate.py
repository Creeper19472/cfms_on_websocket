import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509


# Load root cert
with open("./signing/root_cert.pem", "rb") as root_crtfile:
    root_cert = x509.load_pem_x509_certificate(root_crtfile.read())

# Load root private key
with open("./signing/root_key.pem", "rb") as root_keyfile:
    root_key = serialization.load_pem_private_key(
        root_keyfile.read(), password=None
    )
    # assert type(root_key) == ECPrivateKey
    # ec.generate_private_key()

# Generate our intermediate key
int_key = ec.generate_private_key(ec.SECP256R1())
subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CFMS Intermediate CA Management Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CFMS Intermediate CA"),
    ]
)
int_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(root_cert.subject)
    .public_key(int_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(
        # Our intermediate will be valid for ~3 years
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=365 * 3)
    )
    .add_extension(
        # Allow no further intermediates (path length 0)
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            root_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
        ),
        critical=False,
    )
    .sign(root_key, hashes.SHA256())
)

with open("./signing/int_key.pem", "wb") as f:
    f.write(int_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        # encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ))

with open("./signing/int_cert.pem", "wb") as f:
    f.write(int_cert.public_bytes(serialization.Encoding.PEM))
