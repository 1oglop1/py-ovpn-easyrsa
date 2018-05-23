"""
Tests
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives import hashes
import datetime

from utils import (
    create_private_key, create_csr, create_client_certificate, load_private_key, load_certificate, revoke_certificate,
    generate_crl, revoke_certificates_create_or_update_crl
)

def test_create_private_key():
    key = create_private_key()
    assert isinstance(key, rsa.RSAPrivateKey)


def test_load_private_key(ca_key_file, ca_key):

    key = load_private_key(ca_key_file, passphrase=b'passphrase')

    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.private_numbers() == ca_key.private_numbers()

def test_load_certificate(ca_cert_file, ca_cert):

    cert = load_certificate(ca_cert_file)

    assert isinstance(cert, x509.Certificate)
    assert cert == ca_cert


def test_create_csr(client_private_key, x509_name_attributes, x509_extensions_client):
    client_csr = create_csr(client_private_key, x509_name_attributes, x509_extensions_client)

    assert isinstance(client_csr, x509.CertificateSigningRequest)


def test_create_client_certificate(client_csr, ca_key, ca_cert):

    client_cert = create_client_certificate(client_csr, 123, ca_key, ca_cert)

    assert isinstance(client_cert, x509.Certificate)
    assert ca_cert.subject == client_cert.issuer


def test_revoke_certificate(ca_cert):

    revoked_cert = revoke_certificate(ca_cert)
    assert isinstance(revoked_cert, x509.RevokedCertificate)


def test_generate_crl(ca_cert, ca_key):

    revoked_certs =  [
        x509.RevokedCertificateBuilder() \
            .revocation_date(time=datetime.datetime.today()) \
            .serial_number(x509.random_serial_number()) \
            .build(default_backend()) for x in range(10)
    ]

    crl = generate_crl(ca_cert, ca_key, revoked_certs[0])

    crl2 = generate_crl(ca_cert, ca_key, *revoked_certs)

    assert crl[0].serial_number == revoked_certs[0].serial_number
    assert all(
        [c.serial_number == r.serial_number for c, r in zip(crl2, revoked_certs)]
    )

def test_revoke_certificates_create_or_update_crl(ca_cert, ca_key):

    revoked_batch_1 = [
        x509.RevokedCertificateBuilder() \
            .revocation_date(time=datetime.datetime.today()) \
            .serial_number(x509.random_serial_number()) \
            .build(default_backend()) for x in range(10)
    ]

    revoked_batch_2 = [
        x509.RevokedCertificateBuilder() \
            .revocation_date(time=datetime.datetime.today()) \
            .serial_number(x509.random_serial_number()) \
            .build(default_backend()) for x in range(10)
    ]

    new_crl = revoke_certificates_create_or_update_crl(ca_cert, ca_key, revoked_batch_1)

    assert all(
        [c.serial_number == r.serial_number for c, r in zip(new_crl, revoked_batch_1)]
    )

    updated_crl = revoke_certificates_create_or_update_crl(ca_cert, ca_key, revoked_batch_2, crl_to_update=new_crl)

    revoked_serial_numbers = {rc.serial_number for rc in [*revoked_batch_1, *revoked_batch_2]}
    updated_serial_numers = {rc.serial_number for rc in updated_crl}

    assert revoked_serial_numbers == updated_serial_numers