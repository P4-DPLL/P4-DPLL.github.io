#!/usr/bin/expect

set timeout 10
spawn scp -P 7240 -r python_file/table_clear_and_write.py root@59.77.13.208:/root/bf-sde-9.2.0/HZP

#spawn scp -r python_file/table_clear_and_write.py root@192.168.0.240:/root/JJH/
expect ":"
send "onl\n"
wait