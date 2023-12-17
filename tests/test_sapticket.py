from datetime import datetime, timezone
import pytest
from pysapsso2.crypto import calculate_first_message_digest
from pysapsso2.sapticket import InfoUnitType, SapCodepage, SapTicket
import asn1crypto

# Ticket1 generated with sapssoext 18
# doesn't include a certificate
TICKET1_B64 = (
    "AjQxMTABAAdTQVBVU0VSAgADMDAwAwADU0FQBAAMMjAyMzEyMTcxNTI2BwAEAAAAAgg"
    "AAQEJAAFFDwADMTAwEAADRVJQIAARcG9ydGFsOlBPUlRBTFVTRVKIABNiYXNpY2F1dGhlbnRpY2F0aW9u/"
    "wEPMIIBCwYJKoZIhvcNAQcCoIH9MIH6AgEBMQswCQYFKw4DAhoFADALBgkqhkiG9w0BBwExgdowgdcCAQE"
    "wLDAUMRIwEAYDVQQDDAlweXNhcHNzbzICFGPryGuFRXcXwuhDPK0doq80D2kwMAkGBSsOAwIaBQCgXTAYB"
    "gkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzEyMTcxNTI2MjZaMCMGCSqGSIb"
    "3DQEJBDEWBBTzwTt/ak50JWrl39YsNigNIw78HjAJBgcqhkjOOAQDBC8wLQIVAJhQUSOFJk0GYB6Cs8X/u"
    "AnCU7XKAhQtdVkbekMu9rYLVFHOByXChZDVXA=="
)
TICKET1_MESSAGE_DIGEST = b"\xf3\xc1;\x7fjNt%j\xe5\xdf\xd6,6(\r#\x0e\xfc\x1e"


def test_sapticket_constructor():
    t = SapTicket(b"\x02", b"1100")
    assert t.version == b"\x02"
    assert t.raw_codepage == b"1100"
    assert t.codepage == SapCodepage.ISO8859_1

    # Missing InfoTypes always raise a ValueError exception
    with pytest.raises(ValueError):
        t.signature

    # User not yet set
    with pytest.raises(ValueError):
        t.user

    t.user = "SAPUSER"
    assert t.user == "SAPUSER"


def test_sapticket_load():
    ticket = SapTicket.from_b64(TICKET1_B64)

    # Validate base InfoUnits are extracted correctly
    assert ticket.user == "SAPUSER"
    assert ticket.source_sid == "SAP"
    assert ticket.source_client == "000"
    assert ticket.recipient_sid == "ERP"
    assert ticket.recipient_client == "100"
    assert ticket.creation_time == "202312171526"
    assert ticket.get(InfoUnitType.ID_LANGUAGE).data == b"E"

    # Validate signature details are extracted correctly
    assert isinstance(ticket.signature, asn1crypto.cms.ContentInfo)
    signature = ticket.signature["content"]
    assert int(signature["version"]) == 1
    assert signature["certificates"].native is None
    assert ticket.digital_signature == (
        b"0-\x02\x15\x00\x98PQ#\x85&M\x06`\x1e\x82\xb3\xc5\xff\xb8\t\xc2S\xb5\xca\x02"
        b"\x14-uY\x1bzC.\xf6\xb6\x0bTQ\xce\x07%\xc2\x85\x90\xd5\\"
    )

    assert ticket.signed_attrs[0]["values"].native == ["data"]
    assert ticket.signed_attrs[1]["values"].native == [
        datetime(2023, 12, 17, 15, 26, 26, tzinfo=timezone.utc)
    ]

    assert ticket.signature["content"]["signer_infos"][0]["sid"].chosen[
        "issuer"
    ].native == {"common_name": "pysapsso2"}
    assert (
        ticket.signature["content"]["signer_infos"][0]["sid"]
        .chosen["serial_number"]
        .native
        == 570448220477762429339031219849815937737718458672
    )


def test_sapticket_digest():
    ticket = SapTicket.from_b64(TICKET1_B64)

    assert ticket.signed_attrs[2]["values"].native == [TICKET1_MESSAGE_DIGEST]
    assert ticket.message_digest == TICKET1_MESSAGE_DIGEST
    assert calculate_first_message_digest(ticket).digest() == TICKET1_MESSAGE_DIGEST
