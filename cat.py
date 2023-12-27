from netmiko import ConnectHandler
import re


def COMPLIANCE_CHECK_WITH_EMPTY_RETURN(commandOutput,complianceString):
    if not commandOutput:
        print(f"Not compliant on: {complianceString}")
        return False
    else:
        return True

def COMPLIANCE_CHECK_WITH_NO_RETURN(commandOutput,complianceString):
    outputParse = commandOutput.split(" ")
    if outputParse[0].lower() == "no":
        print(f"Not compliant on: {complianceString}")
        return False
    else:
        return True

def RUN_COMMAND_WITH_EMPTY_RETURN(command,complianceString):
    output = send(f"show running-config | include {command}")
    return COMPLIANCE_CHECK_WITH_EMPTY_RETURN(output,complianceString)

def RUN_COMMAND_WITH_NO_RETURN(command,complianceString):
    output = send(f"show running-config | include {command}")
    return COMPLIANCE_CHECK_WITH_NO_RETURN(output,complianceString)

def AUTH_LINE_PARSER(line):
    pattern = re.compile(r'line (\w+) (\d+(?: \d)?)\n(.*?)(?=\nline|\Z)', re.DOTALL)
    parser = pattern.findall(line)
    return [{'Type':line_type, 'Num':line_num, 'Config':line_config.strip().split('\n')} for line_type, line_num, line_config in parser]



target = input("Enter Target IP Address: ")
username = input("Enter Username: ")
password = input("Enter Password: ")
enable = input("Enter Enable: ")

connection = ConnectHandler(host=target,username=username,password=password,secret=enable,device_type='cisco_ios')
send = connection.send_command
connection.enable()

score = 0


score += RUN_COMMAND_WITH_NO_RETURN("aaa new-model","1.1.1 Enable 'aaa new-model'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("aaa authentication login","1.1.2 Enable 'aaa authentication login'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("aaa authentication enable","1.1.3 Enable 'aaa authentication enable default'")

aaaAuthLine = send("show running-config | sec line | include login authentication")
parsedAaaAuthLine = AUTH_LINE_PARSER(aaaAuthLine)
expectedLines = ["con","tty","vty"]
compliantLines = [entry['Type'] for entry in parsedAaaAuthLine if entry['Type'] in expectedLines]
nonCompliantLines = [line for line in expectedLines if line not in compliantLines]
score += len(compliantLines)
for line in nonCompliantLines:
    print(f"Not compliant in: {line}")

aaaAccountingCommands = ["commands","connection","exec","network","system"]
for index, command in enumerate(aaaAccountingCommands, start = 7):
    score += RUN_COMMAND_WITH_EMPTY_RETURN(f"aaa accounting {command}",f"1.1.{index} Set '{command}'")

#Missing 1.2 Access Rules

bannerCommands = ["exec","login","motd"]
for index, command in enumerate(bannerCommands, start = 1):
    score += RUN_COMMAND_WITH_EMPTY_RETURN(f"begin banner {command}",f"1.3.{index} Set the 'banner-text' for 'banner {command}'")

score += RUN_COMMAND_WITH_EMPTY_RETURN("enable secret","1.4.1 Set 'password' for 'enable secret'")
score += RUN_COMMAND_WITH_NO_RETURN("service password-encryption","1.4.2 Enable 'service password-encryption'")
userSecret = send("show running-config | include username")
userSecretList = userSecret.split("\n")
nonCompliantUserCount = 0
compliantUserCount = 0
for user in userSecretList:
    userDetail = user.split(" ")
    if len(userDetail) < 2:
        nonCompliantUserCount += 1
    elif len(userDetail) >= 3 and userDetail[2] != "secret":
        nonCompliantUserCount += 1
    else:
        compliantUserCount += 1
if compliantUserCount == len(userSecretList):
    score += 1
else:
    print("Not compliant on: 1.4.3 Set 'username secret' for all local users")

snmpEnable = send("show snmp community")
if "snmp agent not enabled" in snmpEnable.lower():
    score += 2
else:
    snmpCommunity = ["private","public"]
    for index, community in enumerate(snmpCommunity,start=2):
        snmpCommunityCommand = send(f"show snmp community | include {community}")
        if not snmpCommunity:
            score += 1
        else:
            print(f"Not compliant on: 1.5.{index} Unset {community} for 'snmp-server community'")



print(score)
print("Closing Connection")
connection.disconnect