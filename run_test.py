#!/usr/bin/python3

import os
import sys
import subprocess
from typing_extensions import Callable
from performance_test import iperf_server_run, iperf_client_run, iperf_kill, check_has_iperf3, ping_test_client_run
from time import sleep
from contextlib import contextmanager
from typing import Iterable, Iterator, Tuple
from traceback import print_exc

def run_cmd(args:str):
    print(f"# {args}")
    sleep(0.01)
    return subprocess.run(args, shell=True, text=True)





class Namespace:
    def __init__(self, name:str, ip_addr:str, port:int,  remote:str, test_ip:str):
        self.veth_name = "veth_"+name
        self.outer_veth_name = "veth_out_"+name
        self.name = name
        self.ip_addr = ip_addr
        self.port = port
        self.remote = remote
        self.test_ip = test_ip


    def spawn_veths(self):
        run_cmd(f'ip netns add {self.name}')
        run_cmd(f'ip link add {self.veth_name} type veth peer name {self.outer_veth_name}')
        run_cmd(f'ip link set {self.veth_name} netns {self.name}')
        run_cmd(f'ip -n {self.name} l set {self.veth_name} up')

    def ip_config(self):
        """Configure the IP addresses of interfaces in this namespace"""
        run_cmd(f"ip -n {self.name} a a {self.ip_addr}/24 dev {self.veth_name}")
        run_cmd(f"ip -n {self.name} l set {self.veth_name} up ")

    def spawn_vpn_debug(self):
        self.spawn_vpn(log_level="debug", print_logs=True)

    def spawn_vpn_perf(self):
        self.spawn_vpn(log_level="critical", print_logs=False)

    def spawn_vpn(self, log_level:str, print_logs:bool):
        cmd = (f'ip netns exec {self.name} ./target/release/vpn -r {self.remote}:{self.port} -l {self.ip_addr}:{self.port} ')
        print(f'# {cmd}')
        #inherit env
        new_env = os.environ.copy()
        #enable full tracing from VPN impl
        new_env.update({"TRACE_LOG":log_level })
        err = sys.stdout if print_logs  else subprocess.DEVNULL
        out = sys.stdout if print_logs  else subprocess.DEVNULL

        self.vpn = subprocess.Popen(cmd.split(), env=new_env, stdout=out, stderr=err)
        #subnet = self.ip_addr.split('.')[:-1]
        #subnet = '.'.join(subnet) + '.0'
        #run_cmd(f"ip -n {self.namespace} r d {subnet}/24")
        #run_cmd(f'ip -n {self.namespace} a')
        #run_cmd(f'ip -n {self.namespace} l')
        #un_cmd(f'ip -n {self.namespace} r')


    def test_bridge(self):
        run_cmd(f'ip -n {self.name} l a br0 type bridge')
        run_cmd(f'ip -n {self.name} l set tap0 master br0')
        run_cmd(f'ip -n {self.name} l set br0 up')
        run_cmd(f'ip -n {self.name} a a {self.test_ip}/24 dev br0')






def add_intra_namespace_bridge(name:str, veths:list[str]):
    up = subprocess.run(f'ip l set {name} up', shell=True, text=True,
                        stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)

    if up.returncode == 1:
        run_cmd(f"ip l a dev {name} type bridge")
        run_cmd(f'ip l set {name} up')

    for ve in veths:
        run_cmd(f"ip l set {ve} master {name}")
        run_cmd(f"ip l set {ve} up")


def set_default_routes(NS1:Namespace, NS2:Namespace):
    run_cmd(f"ip -n {NS1.name} r a default via {NS2.ip_addr} dev {NS1.veth_name}")
    run_cmd(f"ip -n {NS2.name} r a default via {NS1.ip_addr} dev {NS2.veth_name}")



def test(func:Callable):
    from functools import wraps

    @wraps(func)
    def __run(*args, **kwargs):
        print("="*20)
        print("="*20)
        print(f"Test starting {func.__name__}({','.join(args)}, {kwargs})")
        try:
            func(*args, **kwargs)
        except Exception as e:
            print(f"Test {func.__name__}({','.join(args)}, {kwargs}) failed with exception {e}")
            print_exc()
        else:
            print(f"Test {func.__name__}({','.join(args)}, {kwargs}) successful")
        print("="*20)
        print("="*20)
    return __run


@test
def manual_test():
    with namespace_setup() as  namespaces:
        with start_VPN(namespaces) as vpns:
            input("Setup complete, press enter to tear stuff down")


@test
def perf_test_tcp():
    with namespace_setup() as  namespaces:
        with start_VPN(namespaces) as vpns:
            ns1, ns2 = namespaces
            server = iperf_server_run(NS=ns1.name, server_ip=ns1.test_ip)
            try:
                sleep(0.1)
                client = iperf_client_run(NS=ns2.name, client_ip=ns2.test_ip, serv_ip=ns1.test_ip)
                client.wait()
            finally:
                iperf_kill(server)

@test
def correctness_small_packets():
    with namespace_setup() as  namespaces:
        with start_VPN(namespaces) as vpns:
            ns1, ns2 = namespaces
            c = ping_test_client_run(NS=ns1.name,  source_ip=ns1.test_ip, target_ip=ns2.test_ip, packet_size=150)
            rc = c.wait()
            if rc !=0:
                raise RuntimeError("Test failed")

@test
def correctness_big_packets():
    with namespace_setup() as  namespaces:
        with start_VPN(namespaces) as vpns:
            ns1, ns2 = namespaces
            c = ping_test_client_run(NS=ns1.name,  source_ip=ns1.test_ip, target_ip=ns2.test_ip, packet_size=1500)
            rc = c.wait()
            if rc !=0:
                raise RuntimeError("Test failed")

@contextmanager
def namespace_setup(NS1:str = 's1',    NS2:str = 's2',mon_br_name:str = 'monitor_bridge')->Iterator[Tuple[Namespace, Namespace]]:
    namespaces:tuple=()
    try:
        # Create the actual namespaces
        interface1 = Namespace(name= NS1, ip_addr='1.1.1.3', port=7777, remote='1.1.1.4',test_ip='2.2.2.1')
        interface2 = Namespace(name= NS2, ip_addr='1.1.1.4', port=7777, remote='1.1.1.3',test_ip='2.2.2.2')
        namespaces = (interface1, interface2)

        # Create the logical ethernet interfaces to the outside world
        for n in namespaces:
            n.spawn_veths()

        # Create a bridge between namespaces for monitoring (i.e. "internet")
        add_intra_namespace_bridge(mon_br_name, [i.outer_veth_name for i in namespaces])
        sleep(0.1)

        # configure the interfaces between namespaces to be able to send packets via "internet"
        for n in namespaces:
            n.ip_config()

        # set mutual routes between namespaces
        set_default_routes(interface1, interface2)

        # add bridge ports with individual IPs within namespaces for traffic that will go via VPN
        for n in namespaces:
            n.test_bridge()

        yield namespaces


    finally:

        run_cmd(f"killall iperf3")
        run_cmd(f"ip l d {mon_br_name}")

        for n in namespaces:
            run_cmd(f"ip l d {n.outer_veth_name}")
            run_cmd(f'ip netns d  {n.name}')

        res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
        print(f"I've deleted all namespaces I've created before, here's 'ip netns list' output", res.stdout.splitlines())


@contextmanager
def start_VPN(namespaces:Tuple[Namespace, Namespace], profiles:Tuple[str,str]=("debug", "perf")):
    for n, p in zip(namespaces, profiles):
        if p =="debug":
            n.spawn_vpn_debug()
        elif p=="perf":
            n.spawn_vpn_perf()
        else:
            raise NotImplementedError(f"Profile {p} not implemented")

    yield

    # signal the VPN servers to stop
    import signal
    for n in namespaces:
        n.vpn.send_signal(sig=signal.SIGINT)
        sleep(0.5)
        n.vpn.poll()
    sleep(0.5)

    # kill the VPN servers
    for n in namespaces:
        n.vpn.poll()
        n.vpn.terminate()
        n.vpn.kill()


def main():
    if not os.path.exists('./target/release/vpn'):
        exit("There should be a built release binary to test, run ./build.sh as a user to make one")

    if not check_has_iperf3():
        exit("IPerf3 is not detected/functional")

    if os.geteuid() != 0:
        exit("Should run as root user, else namespaces can not be created")


    #run_cmd("ip -n s1 r a default via 1.1.1.2 dev veth1")
    #run_cmd("ip -n s2 r a default via 1.1.1.1 dev veth2")
    #subprocess.Popen(['wireshark','-i',mon_br_name,'-k'])

    correctness_small_packets()
    correctness_big_packets()

    #perf_test_tcp()
    #manual_test()







if __name__ == "__main__":
    main()
