#!/bin/bash
#
# Copyright 2026 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:# www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# End-to-end tests for the hashivault KMS provider against OpenBao, which
# supports key types its Vault Community counterpart does not (ML-DSA).

set -ex

cleanup() {
  echo "cleanup"
  docker compose down
}

trap cleanup ERR

export VAULT_TOKEN=testtoken
export VAULT_ADDR=http://localhost:8210/

echo "starting services"
docker compose config
docker compose up -d --build openbao

count=0

echo -n "waiting up to 60 sec for system to start"
until [ $(docker compose ps openbao | grep -c -e "Up" -e "running") == 1 ];
do
    if [ $count -eq 12 ]; then
       echo "! timeout reached"
       exit 1
    else
       echo -n "."
       sleep 5
       let 'count+=1'
    fi
done

sleep 5

echo
echo "running tests"

export VAULT_TOKEN=testtoken
export VAULT_ADDR=http://localhost:8210/

cd ../..
cd pkg/signature/kms/hashivault
go test -tags e2e -count=1 ./...

cd ../../../../
cd test/e2e

cleanup