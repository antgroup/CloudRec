#!/bin/bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


project_files=("cloudrec_collector_hws_private")

print_banner() {
    echo "#######################################"
    echo "#                                     #"
    echo "#          Welcome to CloudRec!       #"
    echo "#                                     #"
    echo "#######################################"
}

build_and_deploy() {
    local project_name=$1

    log() {
         echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
    }

    log "=========================== Building the ${project_name} ==========================="
    export GO111MODULE=on
    go mod tidy

# macos build and run in mac
#    go build -o "$project_name" main.go
# macos build and run in arm
#    GOOS=linux GOARCH=arm64 go build -o "$project_name" main.go
# macos build and run in x86
    GOARCH=amd64 GOOS=linux go build -o ./deploy_hws_private/"$project_name" main_private.go
}
cd ..
print_banner
for project_file in "${project_files[@]}"; do
    build_and_deploy "$project_file"
done