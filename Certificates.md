#### Certificates
[Generate CSR from Windows Server with SAN (Subject Alternative Name)](https://aventistech.com/2019/08/09/generate-csr-from-windows-server-with-san-subject-alternative-name/)
```

# INTERACTIVE METHOD (PROMPTS FOR CERTIFICATE DETAILS)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365

# NON-INTERACTIVE METHOD (AUTOMATED / SCRIPT-FRIENDLY)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

```
###################
# For the Root CA #
###################
# Create the key and the CA certificate
openssl req -x509 -new -newkey rsa:4096 -nodes \
-keyout ca.key \
-out ca.pem \
-sha512 \
-days 3650 \
-subj "/C=XX/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

###################
# For the App CSR #
###################
# Create the key and the CA certificate
openssl req -new -newkey rsa:4096 -nodes \
-keyout app.key \
-out app.csr \
-sha512 \
-subj "/C=XX/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

# Sign the certificate with CA
openssl x509 -req -in app.csr -sha512 -CA ca.pem -CAkey ca.key -CAcreateserial -out app.pem -days 3650 -extfile <(printf "subjectAltName=IP:192.168.1.10,DNS:abc.xyz.com")
```
#### Split a .pfx File into .pem and .key Files Using OpenSSL
```
# The following command will generate a private key file without a password from your .pfx file (requires password):
openssl pkcs12 -in certificate.pfx -out privateKey.key -nocerts -nodes

# The following command will generate a .pem certificate file from your .pfx file which will include any intermediate and root certificates that may be included in the .pfx file. (requires password):
openssl pkcs12 -in certificate.pfx -out certificate.pem -nokeys -clcerts
```
