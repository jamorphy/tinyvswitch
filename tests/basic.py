import subprocess
import time
import os
import signal
import re

class VSwitch:
    def __init__(self):
        subprocess.run(["sudo", "insmod", "vswitch.ko"])

    def add_interface(self, interface):
        subprocess.run(["sudo", "sh", "-c", f"echo {interface} > /sys/kernel/vswitch/add_interface"])

    def remove_interface(self, interface):
        subprocess.run(["sudo", "sh", "-c", f"echo {interface} > /sys/kernel/vswitch/remove_interface"])

    def cleanup(self):
        subprocess.run(["sudo", "rmmod", "vswitch"])
        
class VM:
    def __init__(self, name, mac, ip):
        self.name = name
        self.mac = mac
        self.ip = ip
        try:
            res = subprocess.run(["sudo", "scripts/create-vm", name, mac, ip], check=True)
        except subprocess.CalledProcessError as e:
            print("Subprocess error creating vm")
            raise

    def ping(self, destination_ip, count=3, interval=1):
        result = subprocess.run(["sudo", "ip", "netns", "exec", self.name,
                                 "ping", "-c", str(count), "-i", str(interval), destination_ip],
                                capture_output=True, text=True)
        return result.stdout

    def start_tcpdump(self):
        self.tcpdump_process = subprocess.Popen(["sudo", "ip", "netns", "exec",
                                                 self.name, "tcpdump", "-i",
                                                 f"{self.name}-eth0", "icmp"],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def stop_tcpdump(self):
        self.tcpdump_process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = self.tcpdump_process.communicate(timeout=5)
            return stdout
        except subprocess.TimeoutExpired:
            self.tcpdump_process.kill()
            stdout, stderr = self.tcpdump_process.communicate()
            return stdout

    def cleanup(self):
        try:
            subprocess.run(["sudo", "scripts/delete-vm", self.name], check=True)
        except subprocess.CalledProcessError as e:
            print("Subprocess error deleting vm")
            raise

def test_vm1_ping_vm2():
    vswitch = VSwitch()
    vm1 = VM("vm1", "00:11:11:11:11:11", "192.168.1.1/24")
    vm2 = VM("vm2", "00:22:22:22:22:22", "192.168.1.2/24")
    
    try:
        # connect the VMs to the switch
        vswitch.add_interface("vm1-eth0-end")
        vswitch.add_interface("vm2-eth0-end")

        vm2.start_tcpdump()
        time.sleep(1)

        ping_out = vm1.ping("192.168.1.2", count=3, interval=0.5)
        time.sleep(3)
        tcpdump_out = vm2.stop_tcpdump()

        assert "3 packets transmitted, 3 received, 0% packet loss" in ping_out

        echo_requests = re.findall(r"ICMP echo request", tcpdump_out)
        num_requests = len(echo_requests)
        assert num_requests == 3

        echo_reply = re.findall(r"ICMP echo reply", tcpdump_out)
        num_reply = len(echo_reply)
        assert num_reply == 3
        
    finally:
        vm1.cleanup()
        vm2.cleanup()
        vswitch.cleanup()


def test_vm1_vm2_vm3_ping():
    vswitch = VSwitch()
    vm1 = VM("vm1", "00:11:11:11:11:11", "192.168.1.1/24")
    vm2 = VM("vm2", "00:22:22:22:22:22", "192.168.1.2/24")
    vm3 = VM("vm3", "00:33:33:33:33:33", "192.168.1.3/24")
    
    try:
        # connect the VMs to the switch
        vswitch.add_interface("vm1-eth0-end")
        vswitch.add_interface("vm2-eth0-end")
        vswitch.add_interface("vm3-eth0-end")

        print('Testing vm1 to vm2 ping')
        vm2.start_tcpdump()
        time.sleep(1)

        vm1_ping_out = vm1.ping("192.168.1.2", count=3, interval=0.5)
        time.sleep(5)
        vm2_tcpdump_out = vm2.stop_tcpdump()

        assert "3 packets transmitted, 3 received, 0% packet loss" in vm1_ping_out

        vm2_echo_requests = re.findall(r"ICMP echo request", vm2_tcpdump_out)
        assert len(vm2_echo_requests) == 3

        vm2_echo_reply = re.findall(r"ICMP echo reply", vm2_tcpdump_out)
        assert len(vm2_echo_reply) == 3

        print('Testing vm3 to vm1 ping')
        vm1.start_tcpdump()
        time.sleep(1)
        
        vm3_ping_out = vm3.ping("192.168.1.1", count=3, interval=0.5)
        time.sleep(5)
        vm1_tcpdump_out = vm1.stop_tcpdump()
        
        assert "3 packets transmitted, 3 received, 0% packet loss" in vm3_ping_out

        vm1_echo_requests = re.findall(r"ICMP echo request", vm1_tcpdump_out)
        assert len(vm1_echo_requests) == 3

        vm1_echo_reply = re.findall(r"ICMP echo reply", vm1_tcpdump_out)
        assert len(vm1_echo_reply) == 3
        
    finally:
        vm1.cleanup()
        vm2.cleanup()
        vm3.cleanup()
        vswitch.cleanup()
        

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)
    
    test_vm1_ping_vm2()
    test_vm1_vm2_vm3_ping()    
    # TODO: mac table tests
    # TODO: Arp tests
    # TODO: different subnet tests
    # TODO: VLAN tests
