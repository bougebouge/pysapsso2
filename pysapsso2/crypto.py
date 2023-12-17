from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from asn1crypto import cms, x509
from Crypto.Hash import SHA1
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from loguru import logger

from pysapsso2.sapticket import SapTicket


def calculate_first_message_digest(ticket: SapTicket) -> SHA1.SHA1Hash:
    """Calculates the first message_digest"""
    return SHA1.new(ticket.dump(include_signature=False))


def calculate_second_message_digest(ticket: SapTicket) -> SHA1.SHA1Hash:
    """Calculates the second message_digest used for signature"""
    return SHA1.new(ticket.signed_attrs.dump())


def get_dsa_key(ticket) -> Optional[DSA.DsaKey]:
    """Returns the first DSA key embedded in the SAP Ticket certificate"""
    signed_data = ticket.signature["content"]
    certs = signed_data["certificates"]
    if certs.native is None:
        # The SAP Ticket doesn't have certificates embedded (it is optional)
        return None
    else:
        # Usually only one certificate is embedded
        cert = certs[0]

        # the algorithm should be DSA
        if cert.chosen.public_key.algorithm != "dsa":
            raise ValueError(
                "Public key algorithm {cert.chosen.public_key.algorithm} not supported "
                "- only dsa is supported."
            )

        # We extract the DSA key information (y=public key, g, p, q)
        public_key = cert.chosen["tbs_certificate"]["subject_public_key_info"][
            "public_key"
        ].native
        param = cert.chosen["tbs_certificate"]["subject_public_key_info"]["algorithm"][
            "parameters"
        ].native

        return DSA.construct(
            (public_key, param["g"], param["p"], param["q"]), consistency_check=True
        )


def _sign_attrs(signed_attrs, key: DSA.DsaKey) -> bytes:
    signer = DSS.new(key, "deterministic-rfc6979", "der")
    return signer.sign(SHA1.new(signed_attrs.dump()))


def validate_signature(ticket, cert: bytes):
    #TODO: validation doesn't work
    key = DSA.import_key(cert)
    verifier = DSS.new(key, "fips-186-3", "der")
    logger.debug(f"Ticket signature={ticket.get_digital_signature()}")
    logger.debug(
        f"Calculated digest for signature={calculate_second_message_digest(ticket).hexdigest()}"
    )
    verifier.verify(
        calculate_second_message_digest(ticket), ticket.get_digital_signature()
    )


def validate_ticket_first_digest(ticket):
    """
    Compares the digest embedded in the ticket
    with the digest we calculate ourselves based on the ticket content
    """
    digest_computed = calculate_first_message_digest(ticket).digest()
    digest_in_ticket = ticket.message_digest
    if digest_in_ticket != digest_computed:
        logger.error("Invalid ticket digest")
        logger.error(f"> Calculated digest = {digest_computed}")
        logger.error(f"> Ticket digest     = {digest_in_ticket}")
        raise ValueError("Invalid internal digest")


def build_signed_data(ticket, private_key: DSA.DsaKey, cert: bytes) -> cms.ContentInfo:
    cert = x509.Certificate.load(cert, strict=True)

    content_type = cms.CMSAttribute({"type": "content_type", "values": ["data"]})
    signing_time = cms.CMSAttribute(
        {
            "type": "signing_time",
            "values": [cms.UTCTime(datetime.now(timezone.utc))],
        }
    )
    message_digest = cms.CMSAttribute(
        {
            "type": "message_digest",
            "values": [calculate_first_message_digest(ticket).digest()],
        }
    )
    signed_attrs_set = cms.CMSAttributes([content_type, signing_time, message_digest])
    signature = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": cms.SignedData(
                {
                    "version": "v1",
                    "digest_algorithms": [{"algorithm": "sha1", "parameters": []}],
                    "encap_content_info": {"content_type": "data"},
                    "signer_infos": [
                        {
                            "version": "v1",
                            "sid": cms.SignerIdentifier(
                                name="issuer_and_serial_number",
                                value={
                                    "issuer": cert["tbs_certificate"]["issuer"],
                                    "serial_number": cert["tbs_certificate"][
                                        "serial_number"
                                    ],
                                },
                            ),
                            "digest_algorithm": {
                                "algorithm": "sha1",
                                "parameters": [],
                            },
                            "signed_attrs": signed_attrs_set,
                            "signature_algorithm": {"algorithm": "sha1_dsa"},
                            "signature": _sign_attrs(
                                signed_attrs_set, private_key
                            ),
                        }
                    ],
                }
            ),
        }
    )
    return signature
