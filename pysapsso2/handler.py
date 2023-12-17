from datetime import datetime, timedelta
from pysapsso2.crypto import build_signed_data
from pysapsso2.sapticket import SapCodepage, SapTicket


class SapTicketHandler:
    def __init__(self, my_sid: str, my_client: str, private_key=None, public_key=None):
        self.sid = my_sid
        self.client = my_client
        self.private_key = private_key
        self.public_key = public_key

    def new(
        self,
        user: str,
        recipient_sid: str = None,
        recipient_client: str = None,
        validity_duration: timedelta = timedelta(hours=0, minutes=10),
        codepage=SapCodepage.UTF8,
    ) -> SapTicket:
        ticket = SapTicket(version=b"\x02", raw_codepage=codepage.dump())
        ticket.user = user
        if recipient_sid is not None:
            ticket.recipient_sid = recipient_sid
        if recipient_client is not None:
            ticket.recipient_client = recipient_client

        hours = int(validity_duration.total_seconds() / 3600)
        minutes = int((validity_duration - timedelta(hours=hours)).total_seconds() / 60)

        ticket.source_client = self.client
        ticket.source_sid = self.sid
        ticket.creation_time = datetime.utcnow().strftime("%Y%m%d%H%M")
        ticket.validity_duration_hours = str(hours)
        ticket.validity_duration_minutes = str(minutes)
        ticket.authscheme = "default"

        ticket.flags = b"\x01"

        assert self.private_key is not None
        assert self.public_key is not None
        ticket.signature = build_signed_data(ticket, self.private_key, self.public_key)
        return ticket
