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

#Take into account manual disabling of required services using the "no" keyword.

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
    snmpRWACL = send("show running-config | include snmp-server community")
    snmpRWACLList = snmpRWACL.split("\n")
    compliantSNMP = 0
    snmpWACL = 0
    for snmp in snmpRWACLList:
        snmpRWParse = snmp.split(" ")
        if len(snmpRWParse) >= 4 and snmpRWParse[3] == "RW":
            pass
        else:
            compliantSNMP += 1
    if compliantSNMP == len(snmpRWACLList):
        score += 1
    else: 
        print("Not compliant on: 1.5.4 Do not set 'RW' for any 'snmp-server community'")
    for snmpACL in snmpRWACLList:
        snmpACLParse = snmpACL.split(" ")
        if len(snmpACLParse) >= 5:
            snmpWACL += 1
            print(snmpACLParse)
        else:
            pass
    if snmpWACL == len(snmpRWACLList):
        score += 1
    else:
        print("Not compliant on: 1.5.5 Set the ACL for each 'snmp-server community'")
    snmpACL = send("show ip access-list")
    if not snmpACL:
        print("Not compliant on: 1.5.6 Create an 'access-list' for use with SNMP")
    else:
        score += 1
    score += RUN_COMMAND_WITH_EMPTY_RETURN("snmp-server host","1.5.7 Set 'snmp-server host' when using SNMP")
    score += RUN_COMMAND_WITH_EMPTY_RETURN("snmp-server enable traps snmp","1.5.8 Set 'snmp-server enable traps snmp'")

    snmpGroups = send("show snmp group | include groupname")
    pattern = re.compile(r'groupname:\s+(\w+)\s+security model:(.*(?:\n|$))')
    matches = pattern.findall(snmpGroups)
    groupList = []

    for group in matches:
        groupname, security_model = group
        security_model_list = [model.strip() for model in security_model.split(",")]
        existing_entry = next((entry for entry in groupList if entry["groupname"] == groupname), None)
        if existing_entry:
            existing_entry["securityModels"].extend(security_model_list)
        else:
            groupList.append({"groupname": groupname, "securityModels": security_model_list})
    compliantGroup = 0 
    for group in groupList:
        # and not any(model in ['v1','v2'] for model in group['securityModels'])
        if any('v3' in model for model in group['securityModels']) and any('priv' in model for model in group['securityModels']):
            compliantGroup += 1
        else:
            print(f"Groupname: {group['groupname']} does not contain 'v3' in its security models.")
    if compliantGroup == len(groupList):
        score += 1    
    else: 
        print("Not compliant on: Set 'priv' for each 'snmp-server group' using SNMPv3")

    snmpUser = send("show snmp user")
    pattern = re.compile(r'User\ name:\s+(?P<username>\w+)\nEngine\ ID:\s+(?P<engineID>[\w\d]+)\nstorage-type:\s+(?P<storageType>\S+\s+\S+)\nAuthentication\ Protocol:\s+(?P<authProtocol>\w+)\nPrivacy\ Protocol:\s+(?P<privacyProtocol>\w+)\nGroup-name:\s+(?P<groupName>\w+)\n', re.VERBOSE)
    matches = pattern.finditer(snmpUser)
    userList = []
    compliantUser = 0
    for match in matches:
        userDict = match.groupdict()
        userList.append(userDict)
    for user in userList:
        if user["privacyProtocol"] == "AES128":
            compliantUser += 1
        else:
            print(f"User {user['username']} does not use AES128")
    if compliantUser == len(userList):
        score += 1
    else:
        print("Not compliant on: Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3")

#Section 2: Control Plane
        
hostname = send("show running-config | include hostname")
hostnameParse = hostname.split(" ")
if hostnameParse[1] == "Router":
    print("Not compliant on: 2.1.1.1.1 Set the 'hostname'")
else:
    score += 1

score += RUN_COMMAND_WITH_EMPTY_RETURN("domain name","2.1.1.1.2 Set the 'ip domain-name'")

modulus = send("show crypto key mypubkey rsa")
if not modulus:
    print("Not compliant on: 2.1.1.3 Set 'modulus' greater than or equal to 2048 for 'crypto key generate rsa'")
else:
    score += 1

sshInfo = send("show ip ssh")
pattern = re.compile(r'SSH (?P<status>Enabled|Disabled) - version (?P<version>\d+\.\d+)\nAuthentication timeout: (?P<timeout>\d+) secs; Authentication retries: (?P<retries>\d+)')
match = pattern.search(sshInfo).groupdict()
if match['status'] == "Enabled":
    sshTimeout = int(match['timeout'])
    sshRetries = int(match['retries'])
    if sshTimeout <= 60:
        print(sshTimeout)
        score += 1
    else:
        print("Not compliant on: 2.1.1.1.4 Set 'seconds' for 'ip ssh timeout'")
    if sshRetries <= 3:
        print(sshRetries)
        score += 1
    else:
        print("2.1.1.1.4 Set maximum value for 'ip ssh authentication-retries'")
    if match['version'] == "2.0":
        score += 1
    else:
        print("Not compliant on: 2.1.1.2 Set version for 'ip ssh version'")
else:
    print("SSH is disabled")

cdp = send("show cdp")
if "cdp is not enabled" in cdp.lower():
    score += 1
else:
    print("Not compliant on: 2.1.2 Set 'no cdp run'")

bootp = send("show running-config | include bootp")
if "no ip bootp server" in bootp.lower():
    score += 1
else:
    print("Not compliant on: 2.1.3 Set 'no ip bootp server'")

dhcp = send("show running-config | include dhcp")
if not dhcp:
    score += 1
else:
    print("Not compliant on: 2.1.4 Set 'no service dhcp'")

identd = send("show running-config | include identd")
if not identd:
    score += 1
else:
    print("Not compliant on: 2.1.5 Set 'no ip identd'")

score += RUN_COMMAND_WITH_EMPTY_RETURN("service tcp-keepalives-in","Not compliant on: 2.1.6 Set 'service-tcp-keepalives-in'")

servicePad = send("show running-config | include service pad")
if "no service pad" in servicePad.lower():
    score += 1
else:
    print("Not compliant on: 2.1.8 Set 'no service pad'")

score += RUN_COMMAND_WITH_EMPTY_RETURN("logging on","2.2.1 Set 'logging on'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("logging buffered","2.2.2 Set 'buffer size' for 'logging buffered'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("logging console critical","2.2.3 Set 'logging console critical'")

logHost = send("show logging | include logging host")
if not logHost:
    print("Not compliant on: 2.2.4 Set IP address for 'logging host'")
else:
    score += 1

timestampDebug = send("show running | include service timestamps")
if not timestampDebug:
    print("Not compliant on: 2.2.6 Set 'service timestamps debug datetime'")
else:
    score += 1

score += RUN_COMMAND_WITH_EMPTY_RETURN("logging source-interface Loopback","2.2.7 Set 'logging source interface'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("ntp authenticate","2.3.1 Set 'ntp authenticate'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("ntp authentication-key","2.3.1.2 Set 'ntp authentication-key'")
score += RUN_COMMAND_WITH_EMPTY_RETURN("ntp trusted-key","2.3.1.3 Set the 'ntp trusted-key'")

ntpServer = send("show running-config | include ntp server")
compliantNtpServer = 0
ntpServerParse = ntpServer.split("\n")
if not ntpServer:
    print("Not compliant on: 2.3.1.4 Set 'key' for each 'ntp server'")
else:
    for server in ntpServerParse:
        serverParse = server.split()
        if len(serverParse) > 3 and serverParse[3] == "key":
            compliantNtpServer += 1
        else:
            pass
if compliantNtpServer == len(ntpServerParse):
    score += 1
else:
    print("Not compliant on: 2.3.1.4 Set 'key' for each 'ntp server'")

score += RUN_COMMAND_WITH_EMPTY_RETURN("show ntp associations","2.3.2 Set 'ip address' for 'ntp server'")

loopbackInt = send("show ip interface brief | include Loopback")
if not loopbackInt:
    print("Not compliant on: 2.4.1 Create a single 'interface loopback'")
else:
    score += 1

tacacsInt = send("show running-config | include tacacs source-interface Loopback")
radiusInt = send("show running-config | include radius source-interface Loopback")
if not tacacsInt and radiusInt:
    print("Not complaint on: 2.4.2 Set AAA 'source-interface'")
else:
    score += 1

score += RUN_COMMAND_WITH_EMPTY_RETURN("ntp source Loopback","2.4.3 Set 'ntp source' to Loopback Interface")
score += RUN_COMMAND_WITH_EMPTY_RETURN("tftp source-interface Loopback","2.4.4 Set 'ip tftp source-interface' to the Loopback Interface")

score += RUN_COMMAND_WITH_EMPTY_RETURN("ip source-route","3.1.1 Set 'no ip source-route'")

proxyArp = send("show ip interface")
pattern = re.compile(r'^(?P<interface>\S+).*?\n(?: {2}(?!Local).*\n)* {2}Proxy ARP is (?P<proxy_arp>enabled|disabled)\s*$', re.MULTILINE)
matches = pattern.findall(proxyArp)
print(matches)
compliantInt = 0
for match in matches:
    if match[1] == "enabled":
        print(f"Interface {match[0]} has Proxy ARP {match[1]}")
    else:
        compliantInt += 1
if compliantInt == len(matches):
    score += 1
else:
    print("Not compliant on: 3.1.2 Set 'no ip proxy-arp")

tunnelInt = send("show ip interface brief | include Tunnel")
if not tunnelInt:
    score += 1
else:
    print("Not compliant on: 3.1.3 Set 'no interface tunnel'")

verifySource = send("show ip interface")
pattern = re.compile(r'^(?P<interfaces>\S+).*?IP verify source reachable-via RX', re.MULTILINE | re.DOTALL)
matches = pattern.finditer(verifySource)
if not matches:
    print("Not compliant on: 3.1.4 Set 'ip verify unicast source reachable-via'")
else:
    for match in matches:
        interface_name = match.group('interfaces')
        print(f"{interface_name} has 'IP verify source reachable-via RX' enabled")
    score += 1

#3.2 Boarder Router Filtering Missing (MANUAL)

routingCheck = send("show running-config | include router")
routingCheckParse = routingCheck.split("\n")
hasEigrp = False
if not routingCheck:
    print("Dynamic routing not enabled")
else:
    for router in routingCheckParse:
        routerParsed = router.split(" ")
        if routerParsed[1] == "eigrp":
            hasEigrp = True
        else:
            print("Other dynamic routing")
    if hasEigrp == True:
        eigrpKey = send("show running-config | section key chain")
        if not eigrpKey:
            print("Not compliant on: 3.3.1.1 Set 'key chain'")
            print("Not compliant on: 3.3.1.2 Set 'key'")
            print("Not compliant on: 3.3.1.3 Set 'key-string'")
        else:
            pattern = re.compile(r'key chain (?P<chain>\S+)\n(?: key (?P<key>\d+)(?:\n  key-string (?P<key_string>\S+))?)?')
            matches = pattern.finditer(eigrpKey)
            result = []
            for match in matches:
                chain = match.group('chain')
                key = match.group('key') or 'null'
                key_string = match.group('key_string') or 'null'
                result.append({'chain': chain, 'key': key, 'key_string': key_string})
                hasIncompleteEIGRP = False
                if key_string == "null":
                    print(f"Chain {match['chain']} does not have a key chain")
                    hasIncompleteEIGRP = True
                else:
                    pass
            if hasIncompleteEIGRP == True:
                score += 2
                print("Not compliant on: 3.3.1.1 Set 'key chain'")
            else:
                score += 3

        eigrpAuth = send("show running-config | section router eigrp")
        pattern = re.compile(r'router eigrp (?P<vrf>[A-Za-z]+\d*[A-Za-z]*)\n(?P<config>.*?)(?=\nrouter|\Z)', re.DOTALL)
        matches = pattern.finditer(eigrpAuth)
        noMode = False
        noChain = False
        wrongInt = False
        for match in matches:
            matchDict = match.groupdict()
            patternAF = re.compile(r' address-family ipv4 unicast autonomous-system (?P<as>\d+)\n(?P<afConfig>.*?)(?=\sexit-address-family|\Z)',re.DOTALL)
            matchAF = patternAF.findall(matchDict['config'])
            if not matchAF:
                print("Not compliant on: 3.3.1.4 Set 'address-family ipv4 autonomous-system'")
                print("Not compliant on: 3.3.1.5 Set 'af-interface default'")
                print("Not compliant on: 3.3.1.6 Set 'authentication key-chain'")
                print("Not compliant on: 3.3.1.7 Set 'authentication mode md5'")
            else:
                print(f"EIGRP VRF {matchDict['vrf']} contains autonomous system {matchAF[0][0]}")
                afConfig = matchAF[0][1]
                score += 1
                patternInt = re.compile(r'af-interface (?P<interface>\S+)(?:\n\s+authentication mode (?P<mode>\S+))?(?:\n\s+authentication key-chain (?P<chain>\S+))?', re.DOTALL)
                matchesInt = patternInt.finditer(afConfig)
                for matchedInt in matchesInt:
                    af_interface = matchedInt.group('interface')
                    auth_mode = matchedInt.group('mode') or "null"
                    auth_key_chain = matchedInt.group('chain') or "null"
            if af_interface != "default":
                wrongInt = True
                print(f"EIGRP VRF {matchDict['vrf']} is using af-interface {af_interface}, instead of 'default'")
            elif af_interface == "default" and (auth_mode != "md5" or auth_mode == "null"):
                noMode = True
                print(f"EIGRP VRF {matchDict['vrf']} is not using md5 authentication mode")
            elif af_interface == "default" and auth_key_chain == "null":
                noChain = True
                print(f"EIGRP VRF {matchDict['vrf']} does not have an authentication key-chain")
            else:
                pass
        if wrongInt == True:
            print("Not compliant on: 3.3.1.5 Set 'af-interface default'")
            print("Not compliant on: 3.3.1.6 Set 'authentication key-chain'")
            print("Not compliant on: 3.3.1.7 Set 'authentication mode md5'")
        elif wrongInt == False and noChain == True and noMode == True:
            print("Not compliant on: 3.3.1.6 Set 'authentication key-chain'")
            print("Not compliant on: 3.3.1.7 Set 'authentication mode md5'")
            score += 1
        elif wrongInt == False and noChain == False and noMode == True:
            print("Not compliant on: 3.3.1.7 Set 'authentication mode md5'")
            score += 2
        elif wrongInt == False and noChain == True and noMode == False:
            print("Not compliant on: 3.3.1.6 Set 'authentication key-chain'")
            score += 2
        else:
            score += 3
        
        score += RUN_COMMAND_WITH_EMPTY_RETURN("key-chain","3.3.1.8 Set 'ip authentication key-chain eigrp'")
        score += RUN_COMMAND_WITH_EMPTY_RETURN("authentication mode","3.3.1.9 Set 'ip authentication mode eigrp'")
        


print(score) 
print("Closing Connection")
connection.disconnect