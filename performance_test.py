import subprocess

def check_has_iperf3():
    try:
        subprocess.run("iperf3",shell=True,text=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def iperf_server_run(NS:str, server_ip:str):
    args = ['ip','netns','exec',NS,'iperf3','-s','--one-off','-D', server_ip]
    print(" ".join(str(element) for element in args))
    s = subprocess.Popen(args)
    return s



def iperf_client_run(NS:str, serv_ip:str, client_ip:str):
    args = ['ip','netns','exec',NS,'iperf3','-c',serv_ip,'-B','--time','3',client_ip,'-b 0','-i 0.125','--bidir']
    print(" ".join(str(element) for element in args))
    c = subprocess.Popen(args)
    return c

def iperf_kill(iperf):
    iperf.kill()
    print('Server R.I.P.')

def ping_test_client_run(NS:str, source_ip:str, target_ip:str, packet_size:int=1500, count:int=10, flood=False):
    args = ['ip','netns','exec',NS,'ping','-I',source_ip, '-c',str(count), '-s', str(packet_size), target_ip]
    if flood:
        args.append('-f')
    print(" ".join(str(element) for element in args))
    c = subprocess.Popen(args)
    return c
