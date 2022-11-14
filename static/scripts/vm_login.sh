#!/bin/bash

username_list=('automation' 'gor' 'dechh' 'grey_user')
password_list=('auto@0702' 'Lhwf^3#J?3rhS+' '2sMcZ3pdTcp5v' 'Oct@2022' '@pj@0702' 'j!em!uvPsc3V=mg^' 'em!uvP1oXAhc3V=mg^4')

user=''
pass=''
for username in ${username_list[@]};
do
    for password in ${password_list[@]};
    do
        Response=$(sshpass -p $password ssh -o StrictHostKeyChecking=no -l $username $1 "whoami")
        # echo $password
        if [ ! -z "$Response" ]; 
        then
            user=$Response;
            pass=$password;
            break 2;
        fi
        # echo $Response
    done
done
echo $user
echo $pass
# sshpass -p $password ssh -o StrictHostKeyChecking=no -l $username '172.16.2.158' "df -h"

# var='grey'
# if [ -z "$var" ]; then echo "NULL"; else echo "Not NULL"; fi
