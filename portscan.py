import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def banner(ip,port):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip,port))
            s.sendall(b"\r\n")
            ban = s.recv(1024)
            return ban.decode(errors="ignore").strip()
    except:
        return ""
    

def res_target(tar):
    try:
        ip = socket.gethostbyname(tar)
        return ip
    except socket.gaierror:
        print("Could not resolve the target: ",tar)
        return None


def sc_work(ip, port):
    if port_scan(ip, port):
        ban = banner(ip,port)
        return (port, serv_detect(port),ban)
    return None


def port_scan(ip,port):
    #xm = input("Enter lower port range:")
    #xh = input("Enter Upper port range")
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    res = s.connect_ex((ip,port))
    s.close()
    if res == 0:
        return True
    return False


def serv_detect(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Not Known"

    
def repo(tar,ip,openp,repn):
    name = repn
    with open(repn,"w") as w:
        w.write(f"Scan report for target: {tar}\n")
        w.write(f"Generated at: {datetime.now()}\n\n")
        if openp:
            for port,ser,ban in openp:
                w.write(f"PORT: {port}\tSTATUS: OPEN\tSERVICE: {ser}\n")
                if ban:
                    w.write(f"      Banner: {ban}\n")   
        else:
            w.write("NO OPEN PORTS FOUND")
    print("Report saved")


def main():
    print("----------------PYTHON-BASED-PORT-SCANNER----------------------\n")
    tar = input("Enter target IP or domain:\n")
    xm = int(input("Enter lower port range: \n"))
    xh = int(input("Enter Upper port range:\n"))
    ip = res_target(tar)
    openp = []
    if ip == None:
        return 
    print(tar,"Target Resolved ->",ip,"\n")
    print("Scanning started at:",datetime.now())
    print("_"*50)
    ports = range(xm,xh+1)
    with ThreadPoolExecutor(max_workers=100) as exc:
        out = exc.map(lambda p: sc_work(ip, p), ports)
    for r in out:
        if r:
            port, ser, ban = r
            print("PORT:\t", port, "STATUS:OPEN\tSERVICE:", ser)
            if banner:
                print("BANNER:",ban)
            openp.append((port, ser,ban))
    print("---------------SCAN-FINISHED------------------------------------")
    rep_n = input("Enter Scan Report name:")
    rep_n = rep_n + ".txt"
    repo(tar,ip,openp,rep_n)

if __name__ == "__main__":
    main()





    
