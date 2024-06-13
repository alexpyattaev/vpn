import subprocess

def test_iperf3():
    try:
        subprocess.run("iperf3",shell=True,text=True)
        return True
    except subprocess.CalledProcessError:
        print("Oh, you need to install iperf3")
        return False

def server_run(NS1, interface1, port):
    args = ['ip','netns','exec',NS1,'iperf3','-s','-D', interface1, f"-p {port}"]
    print(" ".join(str(element) for element in args))
    s = subprocess.Popen(args)
    return s, True



def client_run(NS2, local_iface, remote, port, cport):
    args = ['ip','netns','exec',NS2,'iperf3','-c',remote,'-B',local_iface,'-b 0','-i 0.125',f'-p {port}', "-cport 7777"]
    print(" ".join(str(element) for element in args))
    c = subprocess.Popen(args)
    return c

def iperf_kill(iperf):
    iperf.kill()
    print('Server R.I.P.')

