class DNSQuestion:
    def __init__(self, domain, questionType, questionclass ):
        self.domain = domain
        self.questionType = questionType
        self.questionclass = questionclass
    
    def printSelf(self):
        print("Domain: " + str(self.domain))
        print("QuestionType: " + str(self.questionType))
        print("QuestionClass: " + str(self.questionclass))


class ResourceRecord: 
    def __init__(self, recordName, resouceRecordType, resouceRecordClass, ttl, resourceDataLength, data):
        self.recordName = recordName
        self.resouceRecordType = resouceRecordType
        self.resouceRecordClass = resouceRecordClass
        self.ttl = int.from_bytes(ttl)
        self.resourceDataLength = resourceDataLength
        self.data = data
    
    def printSelf(self):
        print("Record name: " + str(self.recordName))
        print("Type : " + str(self.resouceRecordType))
        print("Class : " + str(self.resouceRecordClass))
        print("Time to Live: " + str(self.ttl))
        print("Data Length: " + str(self.resourceDataLength)) 
        print("Data: " + str(self.data))


def createRecord(dnsPacket):
    recordName = ""

    while True:
        length = int.from_bytes(dnsPacket.read(1)) 
        if length == 192: 
            offset = int.from_bytes(dnsPacket.read(1)) 
            break
        elif length == 0: 
            break
        else:
            recordName += str(dnsPacket.read(length))

    resouceRecordType = int.from_bytes(dnsPacket.read(2))
    
    for type in RRTypes.keys():
        if type == resouceRecordType:
            resouceRecordType = RRTypes[type]
            break 

    resouceRecordClass = int.from_bytes(dnsPacket.read(2))
    
    if resouceRecordClass == 1: 
        resouceRecordClass = "Internet"
    
    ttl = dnsPacket.read(4)
    resourceDataLength = int.from_bytes(dnsPacket.read(2))
    data = dnsPacket.read(resourceDataLength)

    return ResourceRecord(recordName, resouceRecordType, resouceRecordClass, ttl, resourceDataLength, data)

def createQuestion(dnsPacket):
    domain = ""
    while True:
        length = int.from_bytes(dnsPacket.read(1)) 
        if length == 0: 
            break
        else:
            domain += str(dnsPacket.read(length))
    domain = domain.replace("'b'", ".").replace("b'", "").replace("'", "")
    questionType = int.from_bytes(dnsPacket.read(2))

    for type in RRTypes.keys():
        if type == questionType:
            questionType = RRTypes[type]
            break 

    questionclass = int.from_bytes(dnsPacket.read(2))
    if questionclass == 1: 
        questionclass = "Internet"

    return DNSQuestion(domain, questionType, questionclass)

#https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5 
opCodes = {
    0 : "Query",
    1 : "IQuery",
    2 : "Server Status", 
    3 : "Unassigned", 
    4 : "Notify", 
    5 : "Update",
    6 : "DNS Stateful Operations"
}

#https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

rCodes = {
    0 : "Successful Response", 
    1 : "Form Error", 
    2 : "Server Fail", 
    3 : "NXDomain", 
    4 : "NotImp", 
    5 : "Refused", 
    6 : "YXDomain", 
    7 : "YXRRSet", 
    8 : "NXRRSet", 
    9 : "NotAuth", 
    10 : "NotZone", 
    11 : "DSOTYPENI",	
    16 : "BADVERS",	
    16 : "BADSIG",	
    17 : "BADKEY",	
    18 : "BADTIME",	
    19 : "BADMODE",	
    20 : "BADNAME",	
    21 : "BADALG",	
    22 : "BADTRUNC",
    23 : "BADCOOKIE"
}

RRTypes = {
    1 : "A",
    2 : "NS", 
    5: "CNAME",
    6: "SOA", 
    12: "PTR", 
    15: "MX", 
    16: "TXT", 
    28 : "AAAA",
    33 : "SRV"
}

questions = []
awnserResourceRecords = []
authorityResourceRecords = []
additionalResourceRecords = []


with open('ExamplePacket', "rb") as dnsPacket:
    identification = dnsPacket.read(2)
    flag = dnsPacket.read(2)
    numberOfQuestions = int.from_bytes(dnsPacket.read(2))
    numberofAwnserRRs = int.from_bytes(dnsPacket.read(2))
    numberofAuthorityRRs = int.from_bytes(dnsPacket.read(2))
    numberofAdditionalRRs = int.from_bytes(dnsPacket.read(2))
    
    for i in range(numberOfQuestions):
        questions.append(createQuestion(dnsPacket))
    
    for i in range(numberofAwnserRRs):
        awnserResourceRecords.append(createRecord(dnsPacket))

    for i in range(numberofAdditionalRRs):
        authorityResourceRecords.append(createRecord(dnsPacket)) 

    for i in range(numberofAuthorityRRs):
        authorityResourceRecords.append(createRecord(dnsPacket))

print("Identification: " + "0x" + identification.hex())


#Checks i
QR = int.from_bytes(flag, 'big') >> 15

if QR == 1:
    print("Type: Response")
else: 
    print("Type: Request")

#Checks if there is an assigned operation code. If there isn't one then it prints unassinged
operationCode = int.from_bytes(flag, 'big') >> 8 & 0b01111000

assingedOpCode = False
for code in opCodes.keys(): 
    if code == operationCode:
        assingedOpCode = True
        print(opCodes[code])

if not assingedOpCode: 
    print("Unassinged")

#Finds and prints the authoritative flag
AA = int.from_bytes(flag, 'big') >> 8 & 0b00000100

if AA == 1: 
    print("Authoritative Answer")
else:
    print("Non-authoritative Answer")

#Finds and prints the truncated flag
TC = int.from_bytes(flag, 'big') >> 8 & 0b00000010

if TC == 1:
    print("Tuncated")
else:
    print("Untruncated")

#Finds and prints the recusion desired flag
RD = int.from_bytes(flag, 'big') >> 8 & 0b00000001

if RD == 1: 
    print("Recursive Query")
else: 
    print("Iterative Query")

#Finds and prints the recusion Available flag
RA = (int.from_bytes(flag, 'big') & 0b10000000) >> 7 

if RA == 1: 
    print("Recursion Available")
else: 
    print("Recursion Unavailable")

#Finds the return code flag
rCode = (int.from_bytes(flag, 'big') & 0b00001111) 

#Checks if there is an assigned return code. If there isn't one then it prints unassinged
assingedRCode = False
for code in rCodes.keys(): 
    if code == rCode:
        assingedRCode = True
        print(rCodes[code])

if not assingedRCode: 
    print("Unassinged")


print("Number of Questions: " + str(numberOfQuestions) )
print("Number of Anwnser Resource Records: " + str(numberofAwnserRRs))
print("Number of Authority Resource Records: " + str(numberofAuthorityRRs))
print("Number of Additional Resource Records: " + str(numberofAdditionalRRs))

for i in questions: 
    print("----- Question ------")
    i.printSelf()

#Prints all of resource record types
for i in awnserResourceRecords:
    print("----- Awnser Resource Record ------")
    i.printSelf()

for i in authorityResourceRecords:
    print("----- Authority Resource Record ------")
    i.printSelf()
    
for i in additionalResourceRecords:
    print("----- Additional Resource Record ------")
    i.printSelf()
