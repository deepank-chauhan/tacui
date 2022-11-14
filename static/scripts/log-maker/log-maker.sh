#!/bin/bash
sshpass -p $3 ssh -o StrictHostKeyChecking=no -l $1 $2 "bash -s" < ./static/scripts/log-maker/log-components.sh $4 $5 $6 $7
# $4 will be issue type, $5 erlang_version, $6 arguments
