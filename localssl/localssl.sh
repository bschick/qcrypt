#!/bin/bash

#https://betterprogramming.pub/how-to-create-trusted-ssl-certificates-for-your-local-development-13fd5aad29c6

LOCALIP=$(/sbin/ip -o -4 addr list enp0s1 | awk '{print $4}' | cut -d/ -f1)

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
 -x509 -nodes -days 365 -out ca.pem -keyout ca.key \
 -subj "/C=US/ST=Washington/L=BI/O=Reminder Dog/CN=Brad Schick/emailAddress=schickb@gmail.com"

openssl x509 -outform pem -in ca.pem -out ca.crt

cat > v3.ext <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
# Local hosts
DNS.1 = localhost
DNS.2 = 127.0.0.1
DNS.3 = ::1
DNS.4 = t1.quickcrypt.org
DNS.5 = $LOCALIP
EOF

openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
 -keyout localhost.key -out localhost.csr \
 -subj "/C=US/ST=Washington/L=BI/O=Reminder Dog/CN=localhost/emailAddress=schickb@gmail.com"

openssl x509 -req -sha512 -days 365 \
 -extfile v3.ext \
 -CA ca.crt -CAkey ca.key -CAcreateserial \
 -in localhost.csr \
 -out localhost.crt


 # ng serve --host $LOCALIP --ssl --ssl-cert localhost.crt --ssl-key localhost.key
