# pysapsso2
A pure python library for generating SAP Assertion/Logon tickets.

SAP Logon Tickets are authentication tokens accepted by :
 - SAP Netweaver ABAP (SAP GUI, Webdynpro/Fiori, Web Services)
 - SAP Netweaver Java (Web)


This library is an opensource alternative to SAPSSOEXT ([304450 - Single-Sign-On with SAP logon tickets in non-SAP systems](https://me.sap.com/notes/304450))

## How to generate an SAP shortcut
cf. [examples/generate_shortcut.py](examples/generate_shortcut.py)

## How to parse an SAP Logon Ticket
cf. [examples/parse_ticket.py](examples/parse_ticket.py)

## How to generate an SAP Logon Ticket with SAPSSOEXT
For reference here are commands to generate a new key and self-signed certificate for testing SAPSSOEXT:

```
# Generate a DSA key
openssl dsaparam -out sapsso2.key -genkey 1024

# Generate a certificate
openssl req -x509 -new -sha1 -subj "/CN=pysapsso2" -key sapsso2.key -out sapsso2.crt

# Bundle it in a P12 and convert it to SAP PSE
openssl pkcs12 -export -in sapsso2.crt -inkey sapsso2.key -out sapsso2.p12
sapgenpse import_p12 -p sapsso2.pse sapsso2.p12

# Create an SAP Assertion Ticket using SAPSSOEXT
java -cp .\sapssoext.jar com.mysap.sso.SSO2Ticket -i ticket.txt -c -mysid SSO -mycli 000 -exsid ERP -excli 100 -p sapsso2.pse
```

**Notes:**
- SAPSSOEXT supports only 1024 bit keys - if you try with bigger keys, you will get error "MySapCreateAssertionTicket failed: standard error= 9, ssf error= 27"
- Netweaver ABAP and Java support bigger keys (tested up to 4096 bits)

## TODO
- Implement certificate validation
- Write documentation
