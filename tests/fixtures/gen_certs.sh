#!/bin/bash
set -e

# Generate Root key & certificate
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out mock-aws-root.key.pem
openssl req -new -x509 -key mock-aws-root.key.pem -out mock-aws-root.pem -days 3650 -subj "/CN=Mock AWS Nitro Enclaves Root CA"

# Create extension config files
cat > ca.ext << EOF
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
EOF

cat > leaf.ext << EOF
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
EOF

# Generate Intermediate key & CSR
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out mock-aws-intermediate.key.pem
openssl req -new -key mock-aws-intermediate.key.pem -out mock-aws-intermediate.csr -subj "/CN=Mock AWS Nitro Enclaves Intermediate CA"

# Sign Intermediate certificate with Root using ca.ext
openssl x509 -req -in mock-aws-intermediate.csr -CA mock-aws-root.pem -CAkey mock-aws-root.key.pem -CAcreateserial -out mock-aws-intermediate.pem -days 3650 -sha384 -extfile ca.ext

# Generate Leaf key & CSR
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out mock-aws-leaf.key.pem
openssl req -new -key mock-aws-leaf.key.pem -out mock-aws-leaf.csr -subj "/CN=Mock AWS Nitro Enclaves Hypervisor"

# Sign Leaf certificate with Intermediate using leaf.ext
openssl x509 -req -in mock-aws-leaf.csr -CA mock-aws-intermediate.pem -CAkey mock-aws-intermediate.key.pem -CAcreateserial -out mock-aws-leaf.pem -days 3650 -sha384 -extfile leaf.ext

# Clean up CSRs, serial files, and extension configs
rm -f *.csr *.srl ca.ext leaf.ext
echo "Certificates generated successfully!"

