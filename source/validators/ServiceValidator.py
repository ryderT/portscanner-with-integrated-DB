from validators.exceptions.ValidatorException import ValidatorException
class ServiceValidator:
    def __init__(self):
        #self.domains = self.loadDomains("domains_short.txt")
        self.domains = ["RO","COM"]
    def loadDomains(self, filename):
        listOfDomains = []
        with open(filename) as f:
            lines = f.readlines()
            for line in lines:
                listOfDomains.append(line[:-1])
            f.close()
        return listOfDomains

    def validatePortRange(self,lower_limit,upper_limit):
        error_list = ""
        trigger = False
        if not isinstance(upper_limit,int):
            trigger = True
            error_list += "Upper port limit is not an Integer! \n"
        if not isinstance(lower_limit,int):
            trigger = True
            error_list += "Lower port limit is not an Integer! \n"
        if upper_limit < lower_limit:
            trigger = True
            error_list += "The upper port limit is smaller than the lower port limit! \n"
        if lower_limit < 1:
            trigger = True
            error_list += "The lower port limit cannot be smaller than 1! \n"
        if upper_limit > 65535:
            error_list += "The upper port limit cannot be greater than 65535! \n"
            trigger = True

        if trigger:
            raise ValidatorException(error_list)

    def validateHostname(self,hostname):
        if not isinstance(hostname, str):
            raise ValidatorException("Hostname must be a String! \n" )
        if hostname.count('.') == 3:
            for part in hostname.split('.'):
                if part.isdigit():
                    if int(part) > 255 or int(part) < 0:
                        raise ValidatorException("Invalid IP! \n")
                else:
                    raise ValidatorException("Invalid IP! \n")
        else:
            if hostname.split('.')[-1].upper() not in self.domains:
                raise ValidatorException("Invalid Domain! \n")