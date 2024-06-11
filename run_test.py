#!/usr/bin/python3

import os
import subprocess
from performance_test import server_run, client_run, iperf_kill
from time import sleep



def spawn_VPN(namespace:str, remote_addr:str ="3.3.3.3", remote_port:int = 6666):
    cmd = f'ip netns exec ./target/release/vpn --remote-address="{remote_addr}:{remote_port}"'
    print(f"# {cmd}")
    vpn_proc = subprocess.Popen(cmd.split(),
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return vpn_proc

def run_cmd(args:str):
    print(f"# {args}")
    sleep(0.1)
    return subprocess.run(args, shell=True, text=True)


#FIXME: at this point, interfaces needs to be a list of some class instance, else you go insane quick
def add_vpn_interface(namespaces:list[str], interfaces:list[list[str]]):
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

def add_bridge(namespaces:list[str], br:str)->None:
    run_cmd(f'ip l set {br} up')
    x = 0
    for NS in namespaces:
        x += 1
        run_cmd(f"ip l set veth{x}{x} master {br}")
        run_cmd(f"ip l set veth{x}{x} up")


def  CleanAll(NS1:str, NS2:str):
    run_cmd(f'ip netns d  {NS1}')
    run_cmd(f'ip netns d {NS2}')
    #run_cmd(f"ip l d monitor_bridge")
    run_cmd(f"ip l d veth11")
    #run_cmd(f"ip l d veth22")
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f"I'm careful, \nso I've deleted all I've created before, here's 'ip netns list' output", res.stdout.splitlines())



def CreateNameSpaces(namespaces: list[str]):
    run_cmd(f'ip link add veth1 type veth peer name veth11')
    run_cmd(f'ip link add veth2 type veth peer name veth22')
    x = 0
    for NS in namespaces:
        x += 1
        run_cmd(f'ip netns add {NS}')
        run_cmd(f'ip link set veth{x} netns {NS}')
        run_cmd(f'ip -n {NS} a a 1.1.1.{x}/24 dev veth{x}')
        run_cmd(f'ip -n {NS} l set veth{x} up')
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)





def main():


    if not os.path.exists('./target/release/vpn'):
        exit("There should be a built release binary to test, run ./build.sh as a user to make one")

    if os.geteuid() != 0:
        exit("Should run as root user, else namespaces can not be created")

    NS1 = 's1'
    NS2 = 's2'
    vpn1 = 'tap0'
    vpn2 = 'tap1'

    for n in [vpn1, vpn2]:
        run_cmd(f'ip tuntap add mode tap {n}')

    NS1 = 's1'
    mon_br = 'monitor_bridge'
    run_cmd(f"ip l a dev {mon_br} type bridge")
    interface1 = [vpn1, '12.23.34.45']
    interface2 = [vpn2, '23.34.45.56']
    interfaces = [interface1, interface2]

    namespaces = [NS1,NS2]
    CreateNameSpaces(namespaces)
    add_bridge(namespaces, mon_br)


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
