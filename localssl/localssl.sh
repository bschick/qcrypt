#!/bin/bash

#https://betterprogramming.pub/how-to-create-trusted-ssl-certificates-for-your-local-development-13fd5aad29c6

HOSTNAME="t1.quickcrypt.org"
HOSTS_FILE="/etc/hosts"

if grep "^127\.0\.0\.1" "$HOSTS_FILE" | grep -qw "$HOSTNAME"; then
    echo "-> '$HOSTNAME' already exists on 127.0.0.1 line. Skipping."
else
    # If it doesn't, use 'sed' to append it to the end of that specific line
    echo "-> Appending '$HOSTNAME' to 127.0.0.1 line..."
    sudo sed -i -E "/^127\.0\.0\.1/ s/$/ $HOSTNAME/" "$HOSTS_FILE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to update 127.0.0.1 line. Do you have sudo permissions?"
    fi
fi

if grep "^::1" "$HOSTS_FILE" | grep -qw "$HOSTNAME"; then
    echo "-> '$HOSTNAME' already exists on ::1 line. Skipping."
else
    # If it doesn't, use 'sed' to append it to the end of that specific line
    echo "-> Appending '$HOSTNAME' to ::1 line..."
    sudo sed -i -E "/^::1/ s/$/ $HOSTNAME/" "$HOSTS_FILE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to update ::1 line. (This is non-fatal if you don't use IPv6)."
    fi
fi

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
 -x509 -nodes -days 365 -out qcrypt.pem -keyout qcrypt.key \
 -subj "/C=US/ST=Washington/L=BI/O=Reminder Dog/CN=Brad Schick/emailAddress=schickb@gmail.com"

openssl x509 -outform pem -in qcrypt.pem -out qcrypt.crt

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
DNS.4 = $HOSTNAME
EOF

openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
 -keyout localhost.key -out localhost.csr \
 -subj "/C=US/ST=Washington/L=BI/O=Reminder Dog/CN=localhost/emailAddress=schickb@gmail.com"

openssl x509 -req -sha512 -days 365 \
 -extfile v3.ext \
 -CA qcrypt.crt -CAkey qcrypt.key -CAcreateserial \
 -in localhost.csr \
 -out localhost.crt

if [ $? -eq 0 ]; then
    echo "Successfully created localhost.csr and lochost.crt"
else
    echo "Error: Failed to create ssl files"
    exit 1
fi

sudo cp qcrypt.crt /usr/local/share/ca-certificates/.
sudo update-ca-certificates

mkdir -p "$HOME/.pki/nssdb"
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "My Custom CA" -i qcrypt.crt

echo "Done."
