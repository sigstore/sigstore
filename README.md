# Signing Prototype

This is expermiment and a prototype and not intended for use.

## Set up CFSSL

You will need to grab `cfssl` and `cfssljson` CLI tools / server

### Generate a root CA

```
cat > ca.json <<EOF
{
    "CN": "Software Transparency CA",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
    {
      "C": "GB",
      "L": "Wiltshire",
      "O": "Software Transparency CA",
      "OU": "Software Transparency CA Root CA",
      "ST": "England"
    }
   ]
  }
EOF
```

```
cfssl gencert -initca ca.json | cfssljson -bare ca
2021/02/13 17:34:51 [INFO] generating a new CA key and certificate from CSR
2021/02/13 17:34:51 [INFO] generate received request
2021/02/13 17:34:51 [INFO] received CSR
2021/02/13 17:34:51 [INFO] generating key: rsa-2048
2021/02/13 17:34:51 [INFO] encoded CSR
2021/02/13 17:34:51 [INFO] signed certificate with serial number 279026813420683556162576453010610826254146117408
```

### Start the Server

```
cfssl serve --ca ca.pem --ca-key ca-key.pem
```

## Set up your signing cert parameters

```
cat > ~/.signer/profiles.toml <<EOF
rsa_bits = 2048
email = "johndoe@example.com"
common_name = "example.com"
country = "UK"
province = "Wiltshire"
locality = "Chippeham"
organization = "Acme Inc"
organizational_unit = "Widgets"
EOF
```

## sign
```
go run cmd/cli/main.go sign
```

