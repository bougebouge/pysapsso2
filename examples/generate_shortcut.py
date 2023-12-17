from Crypto.PublicKey import DSA
import base64
from asn1crypto import pem

from pysapsso2.handler import SapTicketHandler

SAP_SID = "ERP"
SAP_CLIENT = "100"
SAP_HOSTNAME = "erp_ci"
SAP_INSTANCE_NO = "00"
SAP_USER = "SAPUSER"

with open("tests/keys/sapsso2.crt", "rb") as f:
    cert = f.read()

with open("tests/keys/sapsso2.key", "rb") as f:
    key = f.read()

(_, _, cert) = pem.unarmor(cert)

DSA_key = DSA.import_key(key)
tf = SapTicketHandler("SSO", "000", DSA_key, cert)

# Netweaver ABAP ignores RECIPIENT_SID and RECIPIENT_CLIENT :-)
ticket = tf.new(SAP_USER)
ticket_b64 = base64.b64encode(ticket.dump()).decode()

with open("ticket.sap", "w") as f:
    f.write(
        f"""[System]
Name={SAP_SID}
Client={SAP_CLIENT}
GuiParm=/H/{SAP_HOSTNAME}/S/32{SAP_INSTANCE_NO}
[User]
Language=EN
at="MYSAPSSO2={ticket_b64}"
[Function]
Command=SMEN
Type=Transaction
[Configuration]
Trace=0
[Options]
Reuse=0"""
    )
