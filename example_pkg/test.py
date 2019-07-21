import nmap

def port_scan(ip_address):
    # initialize the port scanner
    nmScan = nmap.PortScanner()
    # scan localhost for ports in range 21-443
    nmScan.scan(ip_address)
    # run a loop to print all the found result about the ports
    for host in nmScan.all_hosts():
        print('Host : %s (%s)' % (host, nmScan[host].hostname()))
        print('State : %s' % nmScan[host].state())
        for protocol in nmScan[host].all_protocols():
            print('----------')
            print('Protocol : %s' % protocol)
            lport = nmScan[host][protocol].keys()
            print(lport)
            # lport.sort()
            for port in lport:
                print('port : %s\tstate : %s\treason : %s\tname : %s' % (
                port, nmScan[host][protocol][port]['state'], nmScan[host][protocol][port]['reason'],
                nmScan[host][protocol][port]['name']))



'''
this code execute only when all_utils.py execute
'''

if __name__ == "__main__":
    try:
        port_scan('167.86.94.236')
    except:
        print('Not found any port.')