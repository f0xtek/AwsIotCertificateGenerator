#!/usr/bin/env bash

set -euo pipefail

POLICY_NAME=$1

for i in $(aws --no-cli-pager iot list-certificates --query 'certificates[*].certificateArn' --output text)
do
  echo "Detaching $POLICY_NAME from $i..."
  aws --no-cli-pager iot detach-policy --policy-name "$POLICY_NAME" --target "$i"
done

echo "Detached all policies!"

for i in $(aws --no-cli-pager iot list-certificates --query 'certificates[*].certificateId' --output text)
do
  echo "Deactivating & deleting certificate ID $i..."
  aws --no-cli-pager iot update-certificate --new-status INACTIVE --certificate-id "$i"
  aws --no-cli-pager iot delete-certificate --certificate-id "$i"
done

echo "All certificates now deleted!"
aws iot list-certificates --no-cli-pager

