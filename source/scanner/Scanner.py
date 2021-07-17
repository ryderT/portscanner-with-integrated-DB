import socket

class PortScanner:
    def __init__(self):
        pass

    def TCP_Scan(self,destination_ip, destination_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            con = s.connect((destination_ip, destination_port))
            return "[TCP]Host: " + str(destination_ip) + ", Port " + str(destination_port) + " is open!"
        except:
           return "[TCP]Host: " + str(destination_ip) + ", Port " + str(destination_port) + " is closed!"
        finally:
            s.close()

    def UDP_Scan(self,destination_ip, destination_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        try:
            con = s.connect((destination_ip, destination_port))
            return "[UDP]Host: " + str(destination_ip) + ", Port " + str(destination_port) + " is open!"
        except:
            return "[UDP]Host: " + str(destination_ip) + ", Port " + str(destination_port) + " is closed!"
        finally:
            s.shutdown(socket.SHUT_RDWR)
            s.close()

    def TCP_RangeScan(self,destination_ip, lower_limit, upper_limit):
        result = []
        if lower_limit == upper_limit:
            upper_limit += 1

        for port in range(lower_limit, upper_limit):
            result.append(self.TCP_Scan(destination_ip,port))
        return result

    def UDP_RangeScan(self,destination_ip, lower_limit, upper_limit):
        result = []
        if lower_limit == upper_limit:
            upper_limit += 1

        for port in range(lower_limit, upper_limit):
            result.append(self.UDP_Scan(destination_ip,port))
        return result

