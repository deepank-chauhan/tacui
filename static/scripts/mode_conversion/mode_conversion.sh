#!/bin/bash

sshpass -p $3 ssh -o StrictHostKeyChecking=no -l $1 $2 "sudo python3 /home/gor/tac_automation/pps-mode-conversion/starter.py $4 $5"