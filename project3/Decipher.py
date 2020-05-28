def XOR(a, b):
    return chr(ord(a) ^ ord(b))

f = open('/home/victim/Public/.Simple_Worm/crack_me.log', 'r')

content = f.read()

for i in range(0, 256):
    tmp = ''
    for j in range(len(content)):
        tmp += XOR(content[j], chr(i))
    flag = tmp.find('1234567')
    if flag >= 0:
        key = i
        break
file_name = 'task1_result.log'
new_tmp = tmp.replace('1234567', '0616078')

cipher = ''
for i in range(len(new_tmp)):
    cipher += XOR(new_tmp[i], chr(key))

print(cipher, file = open(file_name, 'w'), end = '')

f.close()