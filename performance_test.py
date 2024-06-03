import subprocess
import iperf3

def test_iperf3():
    try:
        subprocess.run("iperf3",shell=True,text=True)
    except subprocess.CalledProcessError:
        print("Oh, you need to install iperf3")


def server(NS1, interface1):
    