import subprocess

def test_iperf3():
    try:
        subprocess.run("iperf3",shell=True,text=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print("Oh, you need to install iperf3")
        return False

def server_run(NS:str, server_ip:str):
    args = ['ip','netns','exec',NS,'iperf3','-s','-D', server_ip]
    print(" ".join(str(element) for element in args))
    s = subprocess.Popen(args)
    return s, True



def client_run(NS:str, serv_ip:str, client_ip:str):
    args = ['ip','netns','exec',NS,'iperf3','-c',serv_ip,'-B',client_ip,'-b 0','-i 0.125']
    print(" ".join(str(element) for element in args))
    c = subprocess.Popen(args)
    return c

def iperf_kill(iperf):
    iperf.kill()
    print('Server R.I.P.')

