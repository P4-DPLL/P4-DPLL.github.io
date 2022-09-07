#!/usr/bin/expect

set timeout 10
set pas "onl"
set file [lindex $argv 0]
spawn ssh -p 端口 root@ip
#spawn scp -r setup.py root@192.168.0.240:/root/bf-sde-9.2.0/HZP
expect "*:"
send "$pas\n"
expect "#"
send "cd bf-sde-9.2.0/\n"
expect "#"
send "cd HZP/\n"
#echo $host
expect "#"
send "cp formula_all/$file formula.txt\n"
expect "#"
send "timeout 30s python3 mywrite.py\n"
expect "#"
send "timeout 30s ./setup.sh\n"
expect ">"
send "exit\n"
expect "root@localhost:~/bf-sde-9.2.0/HZP#"
send "exit\n"
expect "root@localhost:~/bf-sde-9.2.0/HZP#"
send "exit\n"
expect "root@localhost:~/bf-sde-9.2.0/HZP#"
send "exit\n"
expect "root@localhost:~/bf-sde-9.2.0/HZP#"
send "exit\n"
interact