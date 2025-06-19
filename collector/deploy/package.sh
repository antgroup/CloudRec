#!/bin/bash
set -euo pipefail

DEPLOY_DIR="$(dirname "$0")"

# Create target directory
mkdir -p "${DEPLOY_DIR}"
echo "Packaging start, compressed files generated at: ${DEPLOY_DIR}"

# Build alicloud deployment directory
echo "Building alicloud deployment..."
if ! (cd "${DEPLOY_DIR}/../alicloud/deploy_alicloud" && ./build.sh); then
    echo "Error: alicloud build failed"
    exit 1
fi

# Compress alicloud deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_alicloud.tar.gz" -C "${DEPLOY_DIR}/../alicloud" deploy_alicloud

# Build alicloud-private deployment directory
echo "Building alicloud-private deployment..."
if ! (cd "${DEPLOY_DIR}/../alicloud-private/deploy_alicloud_private" && ./build.sh); then
    echo "Error: alicloud-private build failed"
    exit 1
fi

# Compress alicloud-private deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_alicloud_private.tar.gz" -C "${DEPLOY_DIR}/../alicloud-private" deploy_alicloud_private

# Build aws deployment directory
echo "Building aws deployment..."
if ! (cd "${DEPLOY_DIR}/../aws/deploy_aws" && ./build.sh); then
    echo "Error: aws build failed"
    exit 1
fi

# Compress aws deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_aws.tar.gz" -C "${DEPLOY_DIR}/../aws" deploy_aws

# Build baidu deployment directory
echo "Building baidu deployment..."
if ! (cd "${DEPLOY_DIR}/../baidu/deploy_baidu" && ./build.sh); then
    echo "Error: baidu build failed"
    exit 1
fi

# Compress baidu deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_baidu.tar.gz" -C "${DEPLOY_DIR}/../baidu" deploy_baidu

# Build gcp deployment directory
echo "Building gcp deployment..."
if ! (cd "${DEPLOY_DIR}/../gcp/deploy_gcp" && ./build.sh); then
    echo "Error: gcp build failed"
    exit 1
fi

# Compress gcp deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_gcp.tar.gz" -C "${DEPLOY_DIR}/../gcp" deploy_gcp

# Build hws deployment directory
echo "Building hws deployment..."
if ! (cd "${DEPLOY_DIR}/../hws/deploy_hws" && ./build.sh); then
    echo "Error: hws build failed"
    exit 1
fi

# Compress hws deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_hws.tar.gz" -C "${DEPLOY_DIR}/../hws" deploy_hws

# Build hws-private deployment directory
#echo "Building hws-private deployment..."
#if ! (cd "${DEPLOY_DIR}/../hws/deploy_hws_private" && ./build.sh); then
#    echo "Error: hws-private build failed"
#    exit 1
#fi

# Compress hws-private deployment directory
#tar -czvf "${DEPLOY_DIR}/deploy_hws_private.tar.gz" -C "${DEPLOY_DIR}/../hws" deploy_hws_private

# Build tencent deployment directory
echo "Building tencent deployment..."
if ! (cd "${DEPLOY_DIR}/../tencent/deploy_tencent" && ./build.sh); then
    echo "Error: tencent build failed"
    exit 1
fi

# Compress tencent deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_tencent.tar.gz" -C "${DEPLOY_DIR}/../tencent" deploy_tencent

# Build ksyun deployment directory
echo "Building ksyun deployment..."
if ! (cd "${DEPLOY_DIR}/../ksyun/deploy_ksyun" && ./build.sh); then
    echo "Error: ksyun build failed"
    exit 1
fi

# Compress ksyun deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_ksyun.tar.gz" -C "${DEPLOY_DIR}/../ksyun" deploy_ksyun

# Build cloudrec deployment directory
echo "Building cloudrec deployment..."
if ! (cd "${DEPLOY_DIR}/../deploy_cloudrec" && ./build.sh); then
    echo "Error: cloudrec build failed"
    exit 1
fi

# Compress cloudrec deployment directory
tar -czvf "${DEPLOY_DIR}/deploy_cloudrec.tar.gz" -C "${DEPLOY_DIR}/../" deploy_cloudrec

echo "Packaging completed, compressed files generated at: ${DEPLOY_DIR}"
ls -lh "${DEPLOY_DIR}"/*.tar.gz