from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import PEMSerializationBackend, DERSerializationBackend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class OvpnConfig:
    """
    Object representing OpenVPN configuration file
    """

    def __init__(self,
                 csr_name_attributes,
                 passphrase=None,
                 client_key=None,
                 client_csr=None,
                 client_cert=None,
                 ca_cert=None,
                 common_part=None
                 ):

        self.common_part = ""
        self.ca_cert = ""


        self.client_key = self.generate_client_key_pair()
        self.client_csr = self.create_client_csr(csr_name_attributes)
        self.client_cert = None # if from file
        self._passphrase = passphrase

    def load_ca_cert(self, file):
        pass

    def load_client_cert(self, file):
        pass

    def generate_client_key_pair(self, bits=2048):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )

        return key

    def create_client_csr(self, name_attributes: list, extesions: list=None) -> x509.CertificateSigningRequest:
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

        if extesions:
            for ext, critical in extesions:
                builder = builder.add_extension(ext, critical)
        csr = builder.sign(self.client_key, hashes.SHA256(), backend=default_backend())
        return csr

    def create_client_cert(self):
        pass

def main():

    # gen private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # save key to file

    with open("TesTkey.pem", "wb") as f:
        f.write(
            key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.PKCS8,
                encryption_algorithm = serialization.BestAvailableEncryption(b"passphrase"),
            )
        )


    # generate CSR
    csr = x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(
        x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'NL'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Noord-Holland"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Amsterdam"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jenda Ltd."),
            x509.NameAttribute(NameOID.COMMON_NAME, "jenda.wtf.com")
        ])
    )

    csr = csr.add_extension(
        x509.SubjectAlternativeName([
            # describe what sites we want this cert for.
            x509.DNSName('jenda.wtf.org'),
            x509.DNSName("www.jenda.wtf.org")
        ]),
        critical=False
    )

    print(csr)
    # Sign the CSR with our private key.
    csr.sign(key, hashes.SHA256(), backend=default_backend())


if __name__ == "__main__":
    main()
    cfg = OvpnConfig()
    cfg.create_client_csr([])