#!/usr/bin/python3

from performance_test import *
import sys


def add_dummy_ifaces():
    subprocess.run('ip l a if1 type dummy', shell=True, text=True)
    subprocess.run('ip l a if2 type dummy', shell=True, text=True)
def add_vpn_interface(namespaces, interfaces):
    for x in range(2):
        subprocess.run(f"ip l set {interfaces[x][0]} netns {namespaces[x]}",shell=True, text=True)
        subprocess.run(f"ip -n {namespaces[x]} a a {interfaces[x][-1]}/24 dev {interfaces[x][0]}",shell=True, text=True)
        subprocess.run(f"ip -n {namespaces[x]} l set {interfaces[x][0]} up ", shell=True, text=True)
        addr = interfaces[x][-1]
        subnet = addr.split('.')[:-1]
        subnet = '.'.join(subnet) + '.0'
        subprocess.run(f"ip -n {namespaces[x]} r d {subnet}/24", shell=True, text=True)
    subprocess.run("ip -n s1 r a default via 1.1.1.2 dev veth1", shell=True, text=True)
    subprocess.run("ip -n s2 r a default via 1.1.1.1 dev veth2", shell=True, text=True)

def add_bridges(namespaces):
    for NS in namespaces:
        subprocess.run(f'ip netns exec {NS} ip l a br0 type bridge ', shell=True, text=True)
        subprocess.run(f'ip netns exec {NS} ip l set br0 up', shell=True, text=True)

def  CleanAll(NS1, NS2):
    subprocess.run(f'ip netns d  {NS1}', shell=True, text=True)
    subprocess.run(f'ip netns d {NS2}', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f"I'm careful, \nso I've deleted all I've created before, here's 'ip netns list' output", res.stdout.splitlines())



def CreateNameSpaces(namespaces):
    subprocess.run(f'ip link add veth1 type veth peer name veth2', shell=True, text=True)
    for NS in namespaces:
        subprocess.run(f'ip netns add  {NS}', shell=True, text=True)
        subprocess.run(f'ip link set veth{NS[-1]} netns {NS}', shell=True, text=True)
        subprocess.run(f'ip -n {NS} a a 1.1.1.{NS[-1]}/24 dev veth{NS[-1]}', shell=True, text=True)
        subprocess.run(f'ip -n {NS} l set veth{NS[-1]} up', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f'NAME SPACES ARE CREATED \n',res.stdout.splitlines(),f'\nveth1 INTERFACE FOR NAMESPACE {namespaces[0]} '
          f'\nveth2 INTERFACE FOR NAMESPACE {namespaces[1]}\n')


import subprocess


def main():
    if subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout.find('root'):
        print(subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout)
        exit("Should run as root user, restart ")
    if len(sys.argv) != 2 :
        print('You need only two arguments, they are VPN interface names')
    vpn2 = sys.argv[2]
    vpn1 = sys.argv[1]
    NS1 = 's1'
    interface1 = [vpn1, '12.23.34.45']
    NS2 = 's2'
    interface2 = [vpn2, '23.34.45.56']
    interfaces = [interface1, interface2]
    namespaces = [NS1,NS2]
    CreateNameSpaces(namespaces)
    #add_dummy_ifaces()


    #add_bridges(namespaces)
    add_vpn_interface(namespaces, interfaces)
    server, running_server=server_run(NS1, interface1[1])
    if running_server:
        client = client_run(NS2, interfaces)
        client.wait()
    iperf_kill(server)
    CleanAll(NS1,NS2)







if __name__ == "__main__":
    main()