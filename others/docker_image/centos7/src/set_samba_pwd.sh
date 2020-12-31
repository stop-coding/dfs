#!/usr/bin/expect
if {$argc < 2} {
    puts "Usage:cmd <username> <password>"
    exit 1
}
set username [lindex $argv 0]
set smbpwd [lindex $argv 1]
spawn smbpasswd -a $username
expect "New SMB password:"
send "$smbpwd\n"
expect "Retype new SMB password:"
send "$smbpwd\n"
expect off





