import subprocess
import os

def test_iperf3():
    try:
        subprocess.run("iperf3",shell=True,text=True)
        return True
    except subprocess.CalledProcessError:
        print("Oh, you need to install iperf3")
        return False

def server_run(NS1, interface1):
    args = ['ip','netns','exec',NS1,'iperf3','-s', interface1]
    print(args)
    s = subprocess.Popen(args)
    return s, True



def client_run(NS2, interfaces):
    args = ['ip','netns','exec',NS2,'iperf3','-c',interfaces[0][1],'-B',interfaces[1][1],'-b 0']
    print(args)
    c = subprocess.Popen(args)
    return c

def iperf_kill(iperf):
    iperf.kill()
    print('Server is dead')

