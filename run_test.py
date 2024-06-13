#!/usr/bin/python3

import os
import subprocess
from performance_test import server_run, client_run, iperf_kill
from time import sleep






def run_cmd(args:str):
    print(f"# {args}")
    sleep(0.1)
    return subprocess.run(args, shell=True, text=True)





class Interface:
    name = ''
    namespace = ''
    ip_addr = ''
    def __init__(self, interface_name:str, namespace:str, ip_addr:str, port:int, remote:str):
        self.name = interface_name
        self.namespace = namespace
        self.ip_addr = ip_addr
        self.port = port
        self.remote = remote
    def interface_to_namespace(self):
        cmd = (f'ip netns exec {self.namespace} ./target/release/vpn -r {self.remote}:{self.port} -l {self.ip_addr}:{self.port} ')
        print(f'# {cmd}')

        subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sleep(1)
        run_cmd(f"ip -n {self.namespace} a a {self.ip_addr}/24 dev {self.name}")
        run_cmd(f"ip -n {self.namespace} l set {self.name} up ")
        #subnet = self.ip_addr.split('.')[:-1]
        #subnet = '.'.join(subnet) + '.0'
        #run_cmd(f"ip -n {self.namespace} r d {subnet}/24")
        #run_cmd(f'ip -n {self.namespace} a')
        #run_cmd(f'ip -n {self.namespace} l')
        #un_cmd(f'ip -n {self.namespace} r')


def add_bridge(br:str):
    up = subprocess.run(f'ip l set {br} up', shell=True, text=True)
    if up.returncode == 1:
        run_cmd(f"ip l a dev {br} type bridge")
        run_cmd(f'ip l set {br} up')
    for x in range(1,3):
        run_cmd(f"ip l set veth{x}{x} master {br}")
        run_cmd(f"ip l set veth{x}{x} up")




def  CleanAll(NS1:str, NS2:str):
    run_cmd(f'ip netns d  {NS1}')
    run_cmd(f'ip netns d {NS2}')
    #run_cmd(f"ip l d monitor_bridge")
    run_cmd(f"ip l d veth11")
    run_cmd(f"ip l d veth22")
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





def main():


    if not os.path.exists('./target/release/vpn'):
        exit("There should be a built release binary to test, run ./build.sh as a user to make one")

    if os.geteuid() != 0:
        exit("Should run as root user, else namespaces can not be created")

    NS1 = 's1'
    NS2 = 's2'
    namespaces = [NS1,NS2]
    vpn1 = 'tap0'
    vpn2 = 'tap1'
    mon_br = 'monitor_bridge'

    CreateNameSpaces(namespaces)
    add_bridge(mon_br)
    run_cmd("ip -n s1 r a default via 1.1.1.2 dev veth1")
    run_cmd("ip -n s2 r a default via 1.1.1.1 dev veth2")
    subprocess.Popen(['wireshark','-i',mon_br,'-k'])
    sleep(1.5)
    interface1 = Interface(vpn1,NS1,'1.1.1.3',7777,'1.1.1.4')
    interface2 = Interface(vpn1,NS2,'1.1.1.4',8888,'1.1.1.3')
    interfaces = [interface1, interface2]


    for interface in interfaces:
        interface.interface_to_namespace()



    server, running_server=server_run(NS1, interface1.ip_addr, interface1.port)
    sleep(0.1)
    if running_server:
        client = client_run(NS2, interface2.ip_addr,interface2.remote, interface1.port, interface2.port,)
        client.wait()
    iperf_kill(server)
    #CleanAll(NS1,NS2)







if __name__ == "__main__":
    main()
