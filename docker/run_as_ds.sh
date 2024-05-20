#!/bin/bash

# Based on https://docs.docker.com/config/containers/multi-service_container
cd animated-adventure

perl -pi -e 's/127.0.0.1/0.0.0.0/g' DeliveryServiceConfig.yaml
perl -pi -e 's/127.0.0.1/0.0.0.0/g' AuthServiceConfig.yaml

./target/release/delivery_service &

./target/release/authentication_service &

wait

exit $?
