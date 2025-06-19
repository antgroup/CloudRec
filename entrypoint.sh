#!/bin/bash

opa_start() {
    chmod +x ./opa
    nohup ./opa run --server --log-level info > /cloudrec/logs/opa.log 2>&1 &
}

server_start() {
    java -jar $JAVA_OPTS ./cloudrec.jar $PARAMS
}

opa_start
server_start

exec bash
