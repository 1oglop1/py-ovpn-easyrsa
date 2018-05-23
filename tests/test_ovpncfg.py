"""
All tests
"""

from ovpncfg import OvpnConfig
from cryptography import x509
from cryptography.x509 import NameOID

def test_create_client_csr():


    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'NL'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Noord-Holland"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Amsterdam"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jenda Ltd."),
        x509.NameAttribute(NameOID.COMMON_NAME, "jenda.wtf.com")
    ]

    cfg = OvpnConfig(attributes)
    print(cfg.client_csr)
    assert isinstance(cfg.client_csr, x509.CertificateSigningRequest)

