from netmiko import ConnectHandler
import re


target = input("Enter Target IP Addres: ")
username = input("Enter Username: ")
password = input("Enter Password: ")
enable = input("Enter Enable: ")
connection = ConnectHandler(host=target,username=username,password=password,secret=enable,device_type='cisco_ios')
command = connection.send_command

score=0

connection.enable()
aaa = command('show running-config | include aaa new-model')
aaaParse = aaa.split(' ')
if aaaParse[0].lower() == 'no':
    print("Not compliant on aaa")
else:
    score += 1

aaaLogin = command('show running-config | include aaa authentication login')
if not aaaLogin:
    print("Not compliant on aaa login")
else:
    score += 1

aaaEnable = command('show running-config | include aaa authentication enable')
if not aaaEnable:
    print("Not compliant on aaa enable")
else:
    score += 1

aaaAuth = command('show running-config | sec line | include login authentication')
pattern = re.compile(r'line (\w+) (\d+(?: \d)?)\n(.*?)(?=\nline|\Z)', re.DOTALL)
parser = pattern.findall(aaaAuth)
parsedAaaAuth = []
for match in parser:
    lineType, lineNum, lineConfig = match
    parsedAaaAuth.append({
        'Type':f"{lineType}",
        'Num':f"{lineNum}",
        'Config':lineConfig.strip().split('\n')
    })
if not parsedAaaAuth or (all(entry['Type'] == 'aux' for entry in parsedAaaAuth) and len(parsedAaaAuth) == 1):
    print("Not compliant")
else:
    nonCompliantLinesInit = ['con','tty','vty']
    for entry in parsedAaaAuth:
        if entry['Type'] == 'con' or entry['Type'] == 'tty' or entry['Type'] == 'vty':
            score += 1
            nonCompliantLinesInit.remove(entry['Type'])
    if not nonCompliantLinesInit:
        print("All Compliant")
    else:
        print(nonCompliantLinesInit)

#1.1.7 Set 'aaa accounting' to log all privileged use commands using 'commands 15' (Automated)
aaaAccountComm = command('show running-config | include aaa accounting commands')
if not aaaAccountComm:
    print("Not compliant on aaa accounting")
else:
    score += 1
#1.1.8 Set 'aaa accounting connection' (Automated)
aaaAccountConn = command('show running-config | include aaa accounting connection')
if not aaaAccountConn:
    print("Not compliant on aaa accounting conn")
else:
    score += 1
#1.1.9 Set 'aaa accounting exec' (Automated)
aaaAccountExec = command('show running-config | include aaa accounting exec')
if not aaaAccountExec:
    print("Not compliant on aaa account exec")
else:
    score += 1
#1.1.10 Set 'aaa accounting network' (Automated)
aaaAccountNetwork = command('show running-config | include aaa account network')
if not aaaAccountNetwork:
    print("Not compliant on aaa account net")
else:
    score += 1
#1.1.11 Set 'aaa accounting system' (Automated)
aaaAccountSys = command('show running-config | include aaa account system')
if not aaaAccountSys:
    print("Not compliant on aaa account sys")
else:
    score += 1


print(score)
print('Closing Connection')
connection.disconnect()