#!/usr/bin/python3
from performance_test import *



def add_vpn_interface(namespaces, interfaces):
    for x in range(1):
        subprocess.run(f"ip l set {interfaces[x]} netns {namespaces[x]}",shell=True, text=True)

def add_bridges(namespaces):
    for NS in namespaces:
        subprocess.run(f'ip netns exec {NS[0]} ip l a br0 type bridge ', shell=True, text=True)
        subprocess.run(f'ip netns exec {NS[0]} ip l set br0 up', shell=True, text=True)

def  CleanAll(NS1, NS2):
    subprocess.run(f'ip netns d  {NS1[0]}', shell=True, text=True)
    subprocess.run(f'ip netns d {NS2[0]}', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f"I'm careful, \nso I've deleted all I've created before, here's 'ip netns list' output", res.stdout.splitlines())



def CreateNameSpaces(namespaces):
    subprocess.run(f'ip link add veth1 type veth peer name veth2', shell=True, text=True)
    for NS in namespaces:
        subprocess.run(f'ip netns add  {NS[0]}', shell=True, text=True)
        subprocess.run(f'ip link set veth{NS[0][-1]} netns {NS[0]}', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f'NAME SPACES ARE CREATED \n',res.stdout.splitlines(),f'\nveth0 INTERFACE FOR NAMESPACE{namespaces[0][0]} '
          f'\nveth1 INTERFACE FOR NAMESPACE {namespaces[0][0]}\n')


import subprocess


def main():
    if subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout.find('root'):
        print(subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout)
        exit("Should run as root user, restart ")
    NS1 = ['s1','1.1.1.1']
    interface1 = 'if1'
    NS2 = ['s2','2.2.2.2']
    interface2 = 'if2'
    interfaces = [interface1, interface2]
    namespaces = [NS1,NS2]
    CreateNameSpaces(namespaces)
    add_bridges(namespaces)
    add_vpn_interface(namespaces, interfaces)





    CleanAll(NS1,NS2)







if __name__ == "__main__":
    main()