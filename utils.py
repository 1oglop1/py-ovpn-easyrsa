from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives import hashes
from typing import List, Tuple
import datetime

x509_extensions = List[Tuple[x509.Extension, bool]]


def create_private_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    """
    Creates private key.

    Parameters
    ----------
    bits
        Key size.

    Returns
    -------
        Private key.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    return key


def save_private_key(
        key: rsa.RSAPrivateKey,
        file_name: Path,
        passphrase: bytes = None,
        encoding: str = 'PEM',
        format: str = 'PKCS8'
):
    """
    Save private key to file.
    Default is PEM key in PKCS8 format.

    Parameters
    ----------
    key
        Private key object.
    file_name
        Output file name.
    passphrase
        Passphrase to encrypt file.
    encoding
        Encoding format.
    format
        Output format.
        Values: PKCS8 or TraditionalOpenSSL
    """
    with open(str(file_name), "wb") as outf:
        outf.write(
            key.private_bytes(
                encoding=Encoding[encoding],
                format=PrivateFormat[format],
                encryption_algorithm=serialization.BestAvailableEncryption(password=passphrase),
            )
        )


def load_private_key(file: Path, enc_format: str = 'PEM', passphrase: bytes = None) -> rsa.RSAPrivateKey:
    """
    Loads private key from file

    Parameters
    ----------
    file
        Path for to file
    enc_format
        Encapsulation format PEM/DER. Default PEM
    passphrase
        Passphrase to decrypt the key.

    Returns
    -------
        Private key.
    """

    with open(file, 'rb') as inf:
        key_data = inf.read()

    if enc_format == 'PEM':
        load_func = serialization.load_pem_private_key
    elif enc_format == 'DER':
        load_func = serialization.load_der_private_key
    else:
        raise TypeError(f"Unsupported encapsulation format {enc_format}")

    key = load_func(key_data, password=passphrase, backend=default_backend())

    if isinstance(key, rsa.RSAPrivateKey):
        return key
    else:
        raise TypeError(f"Object {key} is not RSA {format} private key.")


def load_certificate(file: Path, enc_format: str = 'PEM') -> x509.Certificate:
    """
    Loads certificate from file

    Parameters
    ----------
    file
        Path to certificate file.
    enc_format
        Encapsulation format PEM/DER. Default PEM

    Returns
    -------
        Certificate object.
    """

    with open(file, 'rb') as inf:
        cert_data = inf.read()

    if enc_format == 'PEM':
        load_func = x509.load_pem_x509_certificate
    elif enc_format == 'DER':
        load_func = x509.load_der_x509_certificate
    else:
        raise TypeError(f"Unsupported encapsulation format {enc_format}")

    cert = load_func(cert_data, backend=default_backend())

    if isinstance(cert, x509.Certificate):
        return cert
    else:
        raise TypeError(f"Object {cert} is not {format} certificate")


def load_common_config(file: Path) -> str:
    """
    Load common part of OpenVPN config.

    Parameters
    ----------
    file
        Path to config file.

    Returns
    -------
        String containing common part of VPN config.
    """

    with open(file, 'r') as inf:
        cfg = inf.read()
    return cfg


def save_x509_file(material, file_name: Path, encoding: str = 'PEM'):
    """
    Save x509 object to file.

    Parameters
    ----------
    material
        x509.Certificate, x509.RevokedCertificate, x509.CertificateSigningRequest, x509.CertificateRevocationList
    file_name
        Path to file.
    encoding
        Encapsulation format PEM/DER. Default PEM
    """

    supported_types = (
        x509.Certificate,
        x509.CertificateSigningRequest,
        x509.CertificateRevocationList,
        x509.RevokedCertificate
    )

    if isinstance(material, supported_types):
        with open(file_name, "wb") as outf:
            outf.write(material.public_bytes(Encoding[encoding]))
    else:
        raise ValueError(f"Unsupported object type: {type(material)}")


def create_csr(
        client_key: rsa.RSAPrivateKey,
        name_attributes: list,
        extensions: x509_extensions = None
) -> x509.CertificateSigningRequest:
    """
    Generate client CSR

    Parameters
    ----------
    name_attributes
        List containing cryptography x509.NameAttribute(s)

    extensions
        List of tuples where first items is extension and second (bool) critical
        ``[(cryptography.x509.Extension, False), ...]``.

    Returns
    -------
        Signed Client Certificate Signing Request with client_key
    """
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name(name_attributes))

    if extensions:
        if isinstance(extensions, list) and isinstance(extensions[0], tuple):
            for ext, critical in extensions:
                builder = builder.add_extension(ext, critical)
            csr = builder.sign(client_key, hashes.SHA256(), backend=default_backend())
            return csr
        else:
            raise TypeError(f"Extensions must be type {x509_extensions}")


def create_client_certificate(
        client_csr: x509.CertificateSigningRequest,
        serial_number: int,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate
) -> x509.Certificate:
    """
    Creates client (slave) certificate signed by CA.

    Parameters
    ----------
    client_csr
        Client Certificate Signing Request.
    serial_number
        Client certificate serial number.
        Number must be unique within CA and less than 20 bytes.
    ca_key
        Certificate Authority private key.
    ca_cert
        Certificate Authority certificate.

    Returns
    -------
        Client certificate.
    """

    one_day = datetime.timedelta(1, 0, 0)
    ten_days = datetime.timedelta(10, 0, 0)

    builder = x509.CertificateBuilder(
        issuer_name=ca_cert.subject,
        subject_name=client_csr.subject,
        public_key=client_csr.public_key(),
        serial_number=serial_number,
        not_valid_before=datetime.datetime.today() - one_day,
        not_valid_after=datetime.datetime.today() + ten_days,
    )

    builder = builder.add_extension(
        x509.BasicConstraints(False, path_length=None),
        critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_csr.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)),
        critical=False
    )

    cert = builder.sign(ca_key, hashes.SHA256(), backend=default_backend())
    return cert


def revoke_certificate(cert: x509.Certificate) -> x509.RevokedCertificate:
    """
    Revokes certificate.

    Parameters
    ----------
    cert
        Certificate to revoke.

    Returns
    -------
        Revoked certificate.
    """
    builder = x509.RevokedCertificateBuilder()
    builder = builder.revocation_date(datetime.datetime.today())
    builder = builder.serial_number(cert.serial_number)
    revoked_certificate = builder.build(default_backend())
    return revoked_certificate


def generate_crl(
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        *cert: x509.RevokedCertificate
) -> x509.CertificateRevocationList:

    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.issuer)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)

    for crt in cert:
        builder = builder.add_revoked_certificate(crt)

    crl = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return crl


def revoke_certificates_create_or_update_crl(
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        certs: List[x509.Certificate],
        crl_to_update: x509.CertificateRevocationList = None,

):
    """
    Revoke certificates and generate CRL.

    Parameters
    ----------
    ca_cert
        CA certificate.
    ca_key
        CA key.
    certs
        Certificates to revoke
    crl_to_update
        If specified, function adds revoked certificates from this crl

    Returns
    -------

    """
    # revoke certificates
    revoked_certificates = [revoke_certificate(crt) for crt in certs]

    # add revoked certificates from existing crl
    if crl_to_update:
        revoked_certificates.extend(crl_to_update)


    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.issuer)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)

    # add all revoked certs to new crl
    for crt in revoked_certificates:
        builder = builder.add_revoked_certificate(crt)

    crl = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return crl


def x509_name_attributes():

    return [
        # Provide various details about who we are.
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'NL'),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Noord-Holland"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Amsterdam"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Jenda Ltd."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "jenda.test")
    ]


def x509_extensions():
    return [(
        x509.SubjectAlternativeName([
            # describe what sites we want this cert for.
            x509.DNSName('jenda.wtf.org'),
            x509.DNSName("www.jenda.wtf.org")
        ]),
        False
    )]


if __name__ == '__main__':
    prefix = Path('resources')
    cacrt_file = prefix.joinpath('ca.crt')
    cakey_file = prefix.joinpath('ca.key')
    clientname = 'jenda'
    serial = 0x0C
    commonopt_file = prefix.joinpath('common.txt')
    clientconfig = 'My.ovpn'

    cakey = load_private_key(cakey_file)
    cacert = load_certificate(cacrt_file)

    client_key = create_private_key()
    csr = create_csr(client_key, x509_name_attributes(), extensions=x509_extensions())

    client_cert = create_client_certificate(csr, 666, cakey, cacert)
    print(client_cert)
    # save_x509_file(client_cert, Path('My.crt'))
    revoked = revoke_certificate(client_cert)