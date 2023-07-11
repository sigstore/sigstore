# eHSM-KMS
eHSM-KMS is an End-to-End Distributed and Scalable Cloud KMS (Key Management System) built on top of Intel SGX enclave-based HSM (Hardware Security Module), aka eHSM.

For more details, please refer to: https://github.com/intel/ehsm

Before using eHSM-KMS with the sigstore project, there're certain prerequisites that need to be completed.

## Start EHSM-KMS Service

Please make sure that you've already start the eHSM-KMS service, with the following wikis:
https://github.com/intel/ehsm/blob/main/docs/build-instructions.md

Notes: this need to be done in a SGX capable machine.

## Using eHSM-KMS with Cosign

### gain access to eHSM-KMS
```
curl [--insecure] https://<ehsm-kms addr>:<ehsm-kms port>/ehsm?Action=Enroll

an exmaple response:
{"code":200,"message":"successful","result":{"apikey":"Sy3QFZh6ykv0PdX1pgRXTvyJWbUUQHFy","appid":"244c2d39-8bdd-4867-9bdf-3d92a98060d3"}}
```

### export the eHSM-KMS related variables to the envrionment
```
export EHSM_APPID=244c2d39-8bdd-4867-9bdf-3d92a98060d3
export EHSM_APIKEY=Sy3QFZh6ykv0PdX1pgRXTvyJWbUUQHFy
export EHSM_ADDR=https://<ehsm-kms addr>:<ehsm-kms port>
```

### cosign generate-key-pair
```
 cosign generate-key-pair --kms ehsm://<key_name>
```

### cosign sign and verify
```
cosign sign --key ehsm://<key_name> <img_digest>
cosign verify --key ehsm://<key_name> <img_digest>
```