import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
# from cryptography.x509 import x509.NameOID

import datetime


@pytest.fixture(scope='session')
def client_private_key():
    """
    Generate client private key
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key


@pytest.fixture(scope='session')
def client_private_key_file(tmpdir_factory, client_private_key):
    """
    Dump key to temp file
    """

    key_file = tmpdir_factory.mktemp('test_data').join('client.key')

    with open(str(key_file), "wb") as outf:
        outf.write(
            client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            )
        )

    return key_file


@pytest.fixture(scope='session')
def ca_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key


@pytest.fixture(scope='session')
def ca_key_file(tmpdir_factory, ca_key):
    key_file = tmpdir_factory.mktemp('test_data').join('ca.key')

    with open(str(key_file), "wb") as outf:
        outf.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            )
        )

    return key_file


@pytest.fixture(scope='session')
def client_csr(client_private_key):
    # generate CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'NL'),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Noord-Holland"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Amsterdam"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Company Ltd."),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com")
        ])
    )

    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            # describe what sites we want this cert for.
            x509.DNSName('example.com'),
            x509.DNSName("www.example.com")
        ]),
        critical=False
    )

    csr = builder.sign(client_private_key, hashes.SHA256(), backend=default_backend())

    return csr


@pytest.fixture(scope='session')
def client_csr_file(tmpdir_factory, client_csr):
    # Write CSR to disk
    csr_file = tmpdir_factory.mktemp('test_data').join('client.csr')
    with open(csr_file, "wb") as outf:
        outf.write(client_csr.public_bytes(serialization.Encoding.PEM))

    return csr_file


@pytest.fixture(scope='session')
def ca_cert(ca_key):
    """
    Generate self signed ca.crt object

    Parameters
    ----------
    ca_key - private key

    Returns
    -------
        Self signed certificate.
    """

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"OC"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Amsterdam"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"mysite.com"),
    ])

    serial_number = x509.random_serial_number()
    subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(ca_key.public_key()) \
        .serial_number(serial_number) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ) \
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False, ) \
        .add_extension(subject_key_identifier, critical=False) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False) \
        .add_extension(x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=None,
        decipher_only=None
    ),
        critical=False
    ) \
        .sign(
        # Sign our certificate with our private key
        ca_key, hashes.SHA256(), default_backend()
    )

    return cert



@pytest.fixture(scope='session')
def ca_cert_file(tmpdir_factory, ca_cert):
    # Write our certificate out to disk.
    cert_file = tmpdir_factory.mktemp('test_data').join('ca.crt')
    with open(cert_file, "wb") as outf:
        outf.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    return cert_file


@pytest.fixture(scope='session')
def common_cfg_file(tmpdir_factory):
    cfg = (
        "client\n"
        "dev tun\n"
        "proto tcp\n"
        "remote vpn.example.com 1194\n"
        "resolv-retry infinite\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "comp-lzo\n"
        "verb 3\n"
    )

    common_file = tmpdir_factory.mktem('test_data').join('common.cfg')

    with open(common_file, 'w') as outf:
        outf.write(cfg)

    return common_file


@pytest.fixture(scope='session')
def x509_name_attributes():

    return [
        # Provide various details about who we are.
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'NL'),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Noord-Holland"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Amsterdam"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Jenda Ltd."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "jenda.test")
    ]


@pytest.fixture(scope='session')
def x509_extensions_client():
    return [(
        x509.SubjectAlternativeName([
            # describe what sites we want this cert for.
            x509.DNSName('jenda.wtf.org'),
            x509.DNSName("www.jenda.wtf.org")
        ]),
        False
    )]
