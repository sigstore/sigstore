#!/bin/bash
#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

echo "starting services"
docker-compose up -d

count=0

echo -n "waiting up to 60 sec for system to start"
until [ $(docker-compose ps vault | grep -c "Up") == 1 -a $(docker-compose logs localstack | grep -c Ready) == 1 ];
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
export VAULT_ADDR=http://localhost:8200/

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT=localhost:4566

go test -tags e2e -count=1 ./...

echo "cleanup"
docker-compose down
