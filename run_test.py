#!/usr/bin/python3

from performance_test import server_run, client_run, iperf_kill
from time import sleep



def run_cmd(args:str):
    print(f"# {args}")
    return subprocess.run(args, shell=True, text=True)






def add_vpn_interface(namespaces, interfaces):
    for x in range(2):
        run_cmd(f"ip l set {interfaces[x][0]} netns {namespaces[x]}")
        run_cmd(f"ip -n {namespaces[x]} a a {interfaces[x][-1]}/24 dev {interfaces[x][0]}")
        run_cmd(f"ip -n {namespaces[x]} l set {interfaces[x][0]} up ")
        addr = interfaces[x][-1]
        subnet = addr.split('.')[:-1]
        subnet = '.'.join(subnet) + '.0'
        run_cmd(f"ip -n {namespaces[x]} r d {subnet}/24")
    run_cmd("ip -n s1 r a default via 1.1.1.2 dev veth1")
    run_cmd("ip -n s2 r a default via 1.1.1.1 dev veth2")

def add_bridges(namespaces):
    for NS in namespaces:
        run_cmd(f'ip netns exec {NS} ip l a br0 type bridge ')
        run_cmd(f'ip netns exec {NS} ip l set br0 up')

def  CleanAll(NS1, NS2):
    subprocess.run(f'ip netns d  {NS1}', shell=True, text=True)
    subprocess.run(f'ip netns d {NS2}', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f"I'm careful, \nso I've deleted all I've created before, here's 'ip netns list' output", res.stdout.splitlines())



def CreateNameSpaces(namespaces):
    run_cmd(f'ip link add veth1 type veth peer name veth2')
    for NS in namespaces:
        run_cmd(f'ip netns add  {NS}')
        run_cmd(f'ip link set veth{NS[-1]} netns {NS}')
        run_cmd(f'ip -n {NS} a a 1.1.1.{NS[-1]}/24 dev veth{NS[-1]}')
        run_cmd(f'ip -n {NS} l set veth{NS[-1]} up')
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)



import subprocess


def main():
    if subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout.find('root'):
        print(subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout)
        exit("Should run as root user, restart ")
    NS1 = 's1'
    NS2 = 's2'
    vpn1 = 'tap0'
    vpn2 = 'tap1'

    for n in [vpn1, vpn2]:
        run_cmd(f'ip tuntap add mode tap {n}')

    interface1 = [vpn1, '12.23.34.45']
    interface2 = [vpn2, '23.34.45.56']
    interfaces = [interface1, interface2]
    namespaces = [NS1,NS2]

    CreateNameSpaces(namespaces)


    #add_bridges(namespaces)
    add_vpn_interface(namespaces, interfaces)
    server, running_server=server_run(NS1, interface1[1])
    sleep(0.1)
    if running_server:
        client = client_run(NS2, interfaces)
        client.wait()
    iperf_kill(server)
    CleanAll(NS1,NS2)







if __name__ == "__main__":
    main()
