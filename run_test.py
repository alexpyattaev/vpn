#!/usr/bin/python3
import subprocess


def cleanall(NS1, NS2):
    subprocess.run(f'ip netns d  {NS1[0]}', shell=True, text=True)
    subprocess.run(f'ip netns d {NS2[0]}', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f"I'm careful, \nso I've deleted all I've created before, here's 'ip netns list' output", res.stdout.splitlines())



def CreateNameSpaces(NS1, NS2):
    subprocess.run(f'ip netns add  {NS1[0]}', shell=True, text=True)
    subprocess.run(f'ip netns add  {NS2[0]}', shell=True, text=True)
    subprocess.run(f'ip link add veth0 type veth peer name veth1', shell=True, text=True)
    subprocess.run(f'ip link set veth0 netns {NS1[0]}', shell=True, text=True)
    subprocess.run(f'ip link set veth1 netns {NS2[0]}', shell=True, text=True)
    res = subprocess.run('ip netns list',shell=True, text=True, capture_output=True)
    print(f'NAME SPACES ARE CREATED \n',res.stdout.splitlines(),f'\nveth0 INTERFACE FOR NAMESPACE{NS1[0]} '
          f'\nveth1 INTERFACE FOR NAMESPACE {NS2[0]}\n')


def main():
    if subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout.find('root'):
        print(subprocess.run('whoami',shell=True, text=True, capture_output=True).stdout)
        exit("Should run as root user, restart ")
    NS1 = ['s1','1.1.1.1']
    NS2 = ['s2','2.2.2.2']
    CreateNameSpaces(NS1, NS2)
    






    cleanall(NS1,NS2)







if __name__ == "__main__":
    main()