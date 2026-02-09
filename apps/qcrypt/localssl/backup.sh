#!/bin/bash

#https://betterprogramming.pub/how-to-create-trusted-ssl-certificates-for-your-local-development-13fd5aad29c6

HOSTNAME="t1.quickcrypt.org"
#LOCALIP=$(ip route get 1.1.1.1 | awk '{print $7}')

#if [ -z "$LOCALIP" ]; then
#    echo "Error: Could not determine primary IP address. Is the network up?"
#    exit 1
#fi

#echo "Found primary IP: $LOCALIP"

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
#DNS.5 = $LOCALIP

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

if grep -qw "$HOSTNAME" /etc/hosts; then
    echo "Entry for '$HOSTNAME' already exists in /etc/hosts. No changes made."
else
    LINE_TO_ADD="$LOCALIP	localhost"
    echo "Adding '$LINE_TO_ADD' to /etc/hosts..."

    # We must use 'tee' with 'sudo' to append to a root-owned file.
    # Redirecting tee's stdout to /dev/null keeps the script's output clean.
    echo "$LINE_TO_ADD" | sudo tee -a /etc/hosts > /dev/null

    if [ $? -eq 0 ]; then
        echo "Successfully added entry."
    else
        echo "Error: Failed to write to /etc/hosts. Do you have sudo permissions?"
        exit 2
    fi
fi
