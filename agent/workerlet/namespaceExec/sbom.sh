#!/bin/bash
cd $1
echo $pwd
/usr/local/bin/trivy rootfs --format cyclonedx  .