#!/usr/bin/expect
#!/usr/bin/expect

set timeout 10
spawn ssh -p 7240 root@59.77.13.208
expect "*:"
send "onl\n"
expect "#"
send "cd bf-sde-9.2.0/\n"
expect "#"
send "cd HZP/\n"
send "./setup.sh\n"

expect "tables"
expect ">"
#expect "bfshell>"
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


