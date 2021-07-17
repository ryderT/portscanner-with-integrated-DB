from scanner.Scanner import PortScanner
from validators.ServiceValidator import ServiceValidator
from validators.exceptions.ValidatorException import ValidatorException
from validators.exceptions.ServiceException import ServiceException
from validators.exceptions.DatabaseException import DatabaseException
from database.DatabaseAdapter import DatabaseAdapter
class Service:
    def __init__(self):
        self.PortScanner = PortScanner()
        self.validator = ServiceValidator()
        self.dal = DatabaseAdapter()
    def scanTCP(self,hostname,lower_port,upper_port):
        try:
            lower_port = int(lower_port)
            upper_port = int(upper_port)
            self.validator.validateHostname(hostname)
            self.validator.validatePortRange(lower_port,upper_port)
        except ValidatorException as e:
            raise ServiceException(str(e))
        except ValueError:
            raise ServiceException("Port numbers not numeric!")
        except TypeError:
            raise ServiceException("Port numbers not numeric!")
        return self.PortScanner.TCP_RangeScan(hostname,lower_port,upper_port)

    def scanUDP(self,hostname,lower_port,upper_port):
        try:
            lower_port = int(lower_port)
            upper_port = int(upper_port)
            self.validator.validateHostname(hostname)
            self.validator.validatePortRange(lower_port, upper_port)
        except ValidatorException as e:
            raise ServiceException(str(e))
        except ValueError:
            raise ServiceException("Port numbers not numeric!")
        except TypeError:
            raise ServiceException("Port numbers not numeric!")
        return self.PortScanner.UDP_RangeScan(hostname, lower_port, upper_port)

    def discardClosedPorts(self,listOfFindings):
        for item in listOfFindings:
            if "closed" in item:
                listOfFindings.remove(item)

        return listOfFindings

    def getInformationForPorts(self,port):
        information = self.dal.getAllPortInfo(port)
        response = ''
        for info in information:
            part = ''
            part += 'Information found:\n'
            part += 'Information type: ' + info[0] + '\n'
            part += 'Information description:' + '\n' + info[1] +'\n\n'
            response += part
        return response

    def checkCredentials(self, username, password):
        return self.dal.logIn(username,password)

    def checkRegister(self,username):
        try:
            return self.dal.registerCheck(username)
        except DatabaseException as e:
            raise ServiceException(str(e))

    def register(self, username, password):
        self.dal.registerUser(username,password)
