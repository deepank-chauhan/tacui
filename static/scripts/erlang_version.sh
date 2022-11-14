#!/bin/bash

output=$(sshpass -p $3 ssh -o StrictHostKeyChecking=no -l $1 $2 "echo $3 | sudo -S find /opt/butler_server/ -type d -name 'erts*' | head -n 1") 
echo $output