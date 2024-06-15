#!/usr/bin/python3

import os
import sys
import subprocess
from performance_test import server_run, client_run, iperf_kill
from time import sleep

def run_cmd(args:str):
    print(f"# {args}")
    sleep(0.01)
    return subprocess.run(args, shell=True, text=True)





class Namespace:
    def __init__(self, name:str, ip_addr:str, port:int,  remote:str):
        self.veth_name = "veth_"+name
        self.outer_veth_name = "veth_out_"+name
        self.name = name
        self.ip_addr = ip_addr
        self.port = port
        self.remote = remote
        self.print_logs = False

    def spawn_veths(self):
        run_cmd(f'ip netns add {self.name}')
        run_cmd(f'ip link add {self.veth_name} type veth peer name {self.outer_veth_name}')
        run_cmd(f'ip link set {self.veth_name} netns {self.name}')
        run_cmd(f'ip -n {self.name} l set {self.veth_name} up')

    def ip_config(self):
        """Configure the IP addresses of interfaces in this namespace"""
        run_cmd(f"ip -n {self.name} a a {self.ip_addr}/24 dev {self.veth_name}")
        run_cmd(f"ip -n {self.name} l set {self.veth_name} up ")

    def spawn_vpn(self):
        cmd = (f'ip netns exec {self.name} ./target/release/vpn -r {self.remote}:{self.port} -l {self.ip_addr}:{self.port} ')
        print(f'# {cmd}')
        #inherit env
        new_env = os.environ.copy()
        #enable full tracing from VPN impl
        new_env.update({"TRACE_LOG":"debug" })
        l = sys.stdout if self.print_logs  else None


        subprocess.Popen(cmd.split(), env=new_env, stdout=l, stderr=l)
        #subnet = self.ip_addr.split('.')[:-1]
        #subnet = '.'.join(subnet) + '.0'
        #run_cmd(f"ip -n {self.namespace} r d {subnet}/24")
        #run_cmd(f'ip -n {self.namespace} a')
        #run_cmd(f'ip -n {self.namespace} l')
        #un_cmd(f'ip -n {self.namespace} r')


def add_bridge(name:str, veths:list[str]):
    up = subprocess.run(f'ip l set {name} up', shell=True, text=True,
                        stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)

    if up.returncode == 1:
        run_cmd(f"ip l a dev {name} type bridge")
        run_cmd(f'ip l set {name} up')

    for ve in veths:
        run_cmd(f"ip l set {ve} master {name}")
        run_cmd(f"ip l set {ve} up")




def  CleanAll(namespaces:list[Namespace]):
    run_cmd(f"killall wireshark")
    run_cmd(f"killall iperf3")

    run_cmd(f"ip l d monitor_bridge")


    for n in namespaces:
        run_cmd(f"ip -n {n.name} l d {n.veth_name}")
        run_cmd(f'ip netns d  {n.name}')

    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f"I'm careful, \nso I've deleted all I've created before, here's 'ip netns list' output", res.stdout.splitlines())







def main():


    if not os.path.exists('./target/release/vpn'):
        exit("There should be a built release binary to test, run ./build.sh as a user to make one")

    if os.geteuid() != 0:
        exit("Should run as root user, else namespaces can not be created")

    NS1 = 's1'
    NS2 = 's2'
    vpn1 = 'tap0'
    vpn2 = 'tap1'
    mon_br_name = 'monitor_bridge'
    namespaces=[]
    try:
        interface1 = Namespace(name= NS1, ip_addr='1.1.1.3', port=7777, remote='1.1.1.4')
        interface2 = Namespace(name= NS2, ip_addr='1.1.1.4', port=7777, remote='1.1.1.3')
        namespaces = [interface1, interface2]

        for n in namespaces:
            n.spawn_veths()

        add_bridge(mon_br_name, [i.outer_veth_name for i in namespaces])
        sleep(0.5)
        #run_cmd("ip -n s1 r a default via 1.1.1.2 dev veth1")
        #run_cmd("ip -n s2 r a default via 1.1.1.1 dev veth2")
        #subprocess.Popen(['wireshark','-i',mon_br_name,'-k'])
        sleep(1.5)




        for n in namespaces:
            n.ip_config()

        namespaces[0].print_logs = True

        for n in namespaces:
            n.spawn_vpn()

        input("Press enter to run perf test")

        server, running_server=server_run(NS1, interface1.ip_addr, interface1.port)
        try:
            sleep(0.1)
            if running_server:
                client = client_run(NS2, interface2.ip_addr,interface2.remote, interface1.port, interface2.port,)
                client.wait()
        finally:
            iperf_kill(server)
    finally:
        CleanAll(namespaces)







if __name__ == "__main__":
    main()
