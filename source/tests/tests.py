import unittest
from service.Service import Service
from validators.exceptions.ServiceException import ServiceException


class TestService(unittest.TestCase):
    def testScanTCP(self):
        service = Service()
        dest1 = "google.com"
        port1 = 80
        port2 = 81
        scan1 = service.scanTCP(dest1, port1, port2)
        self.assertEqual(scan1, ["[TCP]Host: " + dest1 + ", Port " + str(port1) + " is open!"])
        try:
            service.scanTCP("google.coms", 80, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanTCP("google.com", "80", 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanTCP("256.0.0.0", 80, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanTCP("google.com", 82, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanTCP("google.com", -1, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanTCP("google.com", 82, 65536)
        except ServiceException:
            self.assertTrue(True)

    def testScanUDP(self):
        service = Service()
        dest1 = "google.com"
        port1 = 80
        port2 = 81
        scan2 = service.scanUDP(dest1, port1, port2)
        self.assertEqual(scan2, ["[UDP]Host: " + dest1 + ", Port " + str(port1) + " is open!"])
        try:
            service.scanUDP("google.coms", 80, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanUDP("google.com", "80", 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanUDP("256.0.0.0", 80, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanUDP("google.com", 82, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanUDP("google.com", -1, 81)
        except ServiceException:
            self.assertTrue(True)
        try:
            service.scanUDP("google.com", 82, 65536)
        except ServiceException:
            self.assertTrue(True)

    def testGetInformationForPorts(self):
        port = "20"
        service = Service()
        response = service.getInformationForPorts(port)
        predicted_response = ""
        predicted_response += 'Information found:\n'
        predicted_response += 'Information type: ' + "vulnerability" + '\n'
        predicted_response += 'Information description:' + '\n' + "FTP PASV \"Pizza Thief\" denial of service and " \
                                                                  "unauthorized data access. Attackers can steal data " \
                                                                  "by connecting to a port that was intended for use " \
                                                                  "by a client." + '\n\n'
        predicted_response += 'Information found:\n'
        predicted_response += 'Information type: ' + "info" + '\n'
        predicted_response += 'Information description:' + '\n' + "ftp-data" + '\n\n'
        self.assertEqual(response, predicted_response)

    def testDiscarClosedPorts(self):
        service = Service()
        l = ["[UDP]Host: " + "google.com" + ", Port " + "80" + " is open!","[UDP]Host: " + "google.com" + ", Port " + "80" + " is closed!"]
        self.assertEqual(["[UDP]Host: " + "google.com" + ", Port " + "80" + " is open!"], service.discardClosedPorts(l))

    def testCheckCredetials(self):
        service = Service()
        self.assertFalse(service.checkCredentials("test1", "test1"))
        self.assertTrue(service.checkCredentials("test3", "test3"))

    def testCheckRegister(self):
        service = Service()
        self.assertTrue(service.checkRegister("admin"))
        try:
            self.assertTrue(service.checkRegister("administrator"))
        except ServiceException:
            self.assertTrue(True)

    def checkRegister(self):
        service = Service()
        service.register("", "admin")
        service.register("admin", "")
        service.register("unittest", "unittest")
        self.assertFalse(service.checkCredentials("", "admin"))
        self.assertFalse(service.checkCredentials("admin", ""))
        self.assertTrue(service.checkCredentials("unittest", "unittest"))

if __name__ == '__main__':
    unittest.main()
