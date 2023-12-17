from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import List, Optional
from loguru import logger

from asn1crypto import cms


# SAP logon ticket data is split into InfoUnit elements
# cf. https://help.sap.com/doc/javadocs_nw73_sps05/7.3.5/en-US/CE/se/com.sap.se/com/sap/security/api/ticket/InfoUnit.html   # noqa: E501
class InfoUnitType(IntEnum):
    ID_USER = 1
    ID_CREATE_CLIENT = 2
    ID_CREATE_NAME = 3
    ID_CREATE_TIME = 4
    ID_VALID_TIME = 5
    ID_RFC = 6
    ID_VALID_TIME_MIN = 7
    ID_FLAGS = 8
    ID_LANGUAGE = 9
    ID_USER_UTF = 10
    ID_CREATE_CLIENT_UTF = 11
    ID_CREATE_NAME_UTF = 12
    ID_CREATE_TIME_UTF = 13
    ID_LANGUAGE_UTF = 14
    ID_RECIPIENT_CLIENT = 15
    ID_RECIPIENT_SID = 16
    ID_PORTAL_USER = 32
    ID_AUTHSCHEME = 136
    ID_SIGNATURE = 255


class SapCodepage(Enum):
    UTF8 = auto()
    ISO8859_1 = auto()
    ISO8859_2 = auto()
    ISO8859_4 = auto()
    ISO8859_5 = auto()
    ISO8859_9 = auto()
    ISO8859_7 = auto()
    ISO8859_8 = auto()
    ISO2022JP = auto()
    Cp500 = auto()
    Cp850 = auto()
    windows_1252 = auto()
    Cp1250 = auto()
    Cp1251 = auto()
    Cp1254 = auto()
    Cp1253 = auto()
    Cp1255 = auto()
    Cp1257 = auto()
    Cp874 = auto()
    Cp1256 = auto()
    SJIS = auto()
    EUC_JP = auto()
    Big5 = auto()
    TIS620 = auto()

    @classmethod
    def from_raw(cls, sap_codepage_str: bytes) -> SapCodepage:
        sap_codepage_mapping = {
            b"4110": SapCodepage.UTF8,
            b"1100": SapCodepage.ISO8859_1,
            b"1140": SapCodepage.ISO8859_1,
            b"1401": SapCodepage.ISO8859_2,
            b"1500": SapCodepage.ISO8859_5,
            b"1610": SapCodepage.ISO8859_9,
            b"1700": SapCodepage.ISO8859_7,
            b"1800": SapCodepage.ISO8859_8,
            b"1900": SapCodepage.ISO8859_4,
            b"8200": SapCodepage.ISO2022JP,
            b"8700": SapCodepage.ISO8859_4,
            b"0120": SapCodepage.Cp500,
            b"1103": SapCodepage.Cp850,
            b"1160": SapCodepage.windows_1252,
            b"1404": SapCodepage.Cp1250,
            b"1504": SapCodepage.Cp1251,
            b"1614": SapCodepage.Cp1254,
            b"1704": SapCodepage.Cp1253,
            b"1804": SapCodepage.Cp1255,
            b"1904": SapCodepage.Cp1257,
            b"8604": SapCodepage.Cp874,
            b"8704": SapCodepage.Cp1256,
            b"8000": SapCodepage.SJIS,
            b"8100": SapCodepage.EUC_JP,
            b"8300": SapCodepage.Big5,
            b"8600": SapCodepage.TIS620,
        }
        return sap_codepage_mapping[sap_codepage_str]

    @property
    def native(self) -> str:
        sap_codepage_mapping = {
            SapCodepage.ISO8859_1: "iso8859-1",
            SapCodepage.UTF8: "utf-8",
        }
        try:
            return sap_codepage_mapping[self]
        except KeyError:
            raise KeyError(f"Unknown SAP codepage {self}")

    def dump(self) -> bytes:
        sap_codepage_mapping = {
            SapCodepage.UTF8: b"4110",
            SapCodepage.ISO8859_1: b"1100",
        }
        return sap_codepage_mapping[self]


def b2i(b: bytes) -> int:
    """Converts bytes to int"""
    return int.from_bytes(b, byteorder="big")


def i2b(i: int, l: int):
    """Converts int to bytes"""
    return (i).to_bytes(l, byteorder="big")


@dataclass
class InfoUnit:
    type: InfoUnitType
    data: bytes

    @property
    def length(self):
        return len(self.data)

    def dump(self):
        return i2b(self.type.value, 1) + i2b(self.length, 2) + self.data


@dataclass
class SapTicket:
    """Represents a SAP Assertion/Logon Ticket."""

    version: bytes
    raw_codepage: bytes
    info_units: List(InfoUnit) = field(default_factory=list)

    def get(self, iu_type: InfoUnitType) -> InfoUnit:
        for info_unit in self.info_units:
            if info_unit.type == iu_type:
                return info_unit
        raise ValueError("InfoUnit not found")

    def set(self, iu_type: InfoUnitType, value: bytes):
        for info_unit in self.info_units:
            if info_unit.type == iu_type:
                info_unit.data = value
                break
        else:
            self.info_units.append(InfoUnit(iu_type, value))

    def _b2s(self, b: bytes) -> str:
        """Converts bytes to string"""
        python_cp = self.codepage.native
        return b.decode(python_cp)

    def _s2b(self, s: str) -> bytes:
        """Converts string to bytes"""
        python_cp = self.codepage.native
        return s.encode(python_cp)

    @property
    def codepage(self):
        return SapCodepage.from_raw(self.raw_codepage)

    @property
    def authscheme(self) -> str:
        info_unit = self.get(InfoUnitType.ID_AUTHSCHEME)
        return self._b2s(info_unit.data)

    @authscheme.setter
    def authscheme(self, v: str):
        self.set(InfoUnitType.ID_AUTHSCHEME, self._s2b(v))

    @property
    def recipient_sid(self) -> str:
        info_unit = self.get(InfoUnitType.ID_RECIPIENT_SID)
        return self._b2s(info_unit.data)

    @recipient_sid.setter
    def recipient_sid(self, v: str):
        self.set(InfoUnitType.ID_RECIPIENT_SID, self._s2b(v))

    @property
    def recipient_client(self) -> str:
        info_unit = self.get(InfoUnitType.ID_RECIPIENT_CLIENT)
        return self._b2s(info_unit.data)

    @recipient_client.setter
    def recipient_client(self, v: str):
        self.set(InfoUnitType.ID_RECIPIENT_CLIENT, self._s2b(v))

    @property
    def flags(self) -> bytes:
        info_unit = self.get(InfoUnitType.ID_FLAGS)
        return info_unit.data

    @flags.setter
    def flags(self, v: bytes):
        self.set(InfoUnitType.ID_FLAGS, v)

    @property
    def user(self) -> Optional[str]:
        info_unit = self.get(InfoUnitType.ID_USER)
        return self._b2s(info_unit.data)

    @user.setter
    def user(self, v: str):
        self.set(InfoUnitType.ID_USER, self._s2b(v))

    @property
    def source_client(self) -> str:
        info_unit = self.get(InfoUnitType.ID_CREATE_CLIENT)
        return self._b2s(info_unit.data)

    @source_client.setter
    def source_client(self, v: str):
        self.set(InfoUnitType.ID_CREATE_CLIENT, self._s2b(v))

    @property
    def source_sid(self) -> str:
        info_unit = self.get(InfoUnitType.ID_CREATE_NAME)
        return self._b2s(info_unit.data)

    @source_sid.setter
    def source_sid(self, v: str):
        self.set(InfoUnitType.ID_CREATE_NAME, self._s2b(v))

    @property
    def creation_time(self) -> str:
        info_unit = self.get(InfoUnitType.ID_CREATE_TIME)
        return self._b2s(info_unit.data)

    @creation_time.setter
    def creation_time(self, v: str):
        self.set(InfoUnitType.ID_CREATE_TIME, self._s2b(v))

    @property
    def validity_duration_hours(self) -> str:
        info_unit = self.get(InfoUnitType.ID_VALID_TIME)
        return self._b2s(info_unit.data)

    @validity_duration_hours.setter
    def validity_duration_hours(self, v: str):
        self.set(InfoUnitType.ID_VALID_TIME, self._s2b(v))

    @property
    def validity_duration_minutes(self) -> str:
        info_unit = self.get(InfoUnitType.ID_VALID_TIME_MIN)
        return self._b2s(info_unit.data)

    @validity_duration_minutes.setter
    def validity_duration_minutes(self, v: str):
        self.set(InfoUnitType.ID_VALID_TIME_MIN, self._s2b(v))

    @property
    def signature(self) -> cms.ContentInfo:
        info_unit = self.get(InfoUnitType.ID_SIGNATURE)
        return cms.ContentInfo.load(info_unit.data)

    @signature.setter
    def signature(self, v: cms.ContentInfo):
        self.set(InfoUnitType.ID_SIGNATURE, v.dump())

    @classmethod
    def from_b64(cls, ticket_b64: str) -> SapTicket:
        """
        Creates a SapTicket object from a serialised SAP Logon Ticket
        (read for example from a MYSAPSSO2 cookie)
        """
        ticket_b64 = ticket_b64.replace("!", "/")
        ticket_bytes = base64.b64decode(ticket_b64, validate=True)

        (version, raw_codepage) = struct.unpack("c4s", ticket_bytes[0:5])

        ticket = cls(version, raw_codepage)
        logger.debug(
            f"New ticket version={version} codepage={raw_codepage} len={len(ticket_bytes)}"
        )
        i = 5

        # loop through the ticket and extract all the InfoUnits
        while i < len(ticket_bytes):
            iu_l = b2i(ticket_bytes[i + 1 : i + 3])  # length of the InfoUnit

            iu_type = InfoUnitType(ticket_bytes[i])  # type of the InfoUnit
            iu_value = ticket_bytes[i + 3 : i + 3 + iu_l]  # data of the InfoUnit

            if len(iu_value) != iu_l:
                raise ValueError(
                    f"Invalid length for InfoType {iu_type.name}. "
                    f"Expected {iu_l} bytes, found {len(iu_value)} bytes"
                )

            ticket.set(iu_type, iu_value)
            logger.debug(f"Adding InfoType {iu_type.name} len={iu_l}")
            i += (
                3 + iu_l
            )  # 1 byte for the InfoUnit id + 2 bytes for the InfoUnit length = 3 bytes
        return ticket

    def _dump_info_units(self, include_signature=True):
        ticket_data = b""
        for info_unit in self.info_units:
            if info_unit.type == InfoUnitType.ID_SIGNATURE and not include_signature:
                continue
            ticket_data += info_unit.dump()
        return ticket_data

    def dump(self, include_signature: bool = True) -> bytes:
        return (
            self.version + self.raw_codepage + self._dump_info_units(include_signature)
        )

    @property
    def message_digest(self) -> str:
        """Returns the message_digest present in the SAP Ticket"""
        data = self.signature["content"]

        # The digest algorithm should be sha1
        algo = data["signer_infos"][0]["digest_algorithm"]["algorithm"].native
        if algo != "sha1":
            raise ValueError(
                "Digest algorithm {algo} not supported - only sha1 is supported"
            )

        # We loop through signer_infos to find the message_digest
        for attr in data["signer_infos"][0]["signed_attrs"]:
            if attr["type"].native == "message_digest":
                return attr["values"][0].native
        raise ValueError("Message digest not found in the SAP Ticket signature")

    @property
    def digital_signature(self) -> bytes:
        """Returns the Digital Signature of the SAP Ticket"""
        info = self.signature
        signed_data = info["content"]
        return signed_data["signer_infos"][0]["signature"].native

    @property
    def signed_attrs(self) -> cms.CMSAttribute:
        data = self.signature["content"]
        signed_attrs = data["signer_infos"][0]["signed_attrs"]
        content_type, signing_time, message_digest = None, None, None
        for attr in signed_attrs:
            if attr["type"].native == "content_type":
                content_type = attr
            if attr["type"].native == "signing_time":
                signing_time = attr
            if attr["type"].native == "message_digest":
                message_digest = attr
        assert content_type is not None
        assert signing_time is not None
        assert message_digest is not None
        signed_attrs_set = cms.CMSAttributes(
            [content_type, signing_time, message_digest]
        )
        return signed_attrs_set
