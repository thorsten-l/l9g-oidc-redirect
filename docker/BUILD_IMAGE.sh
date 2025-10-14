#!/bin/bash

( cd ..; mvn clean package  )
cp ../target/l9g-oidc-redirect.jar .
docker build -t l9g-oidc-redirect:latest .
