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
    11  : "DSOTYPENI",	
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


with open('ExamplePacket', "rb") as dnsPacket:
    identification = dnsPacket.read(2)
    flag = dnsPacket.read(2)
    numberOfQuestions = int.from_bytes(dnsPacket.read(2))
    numberofAwnserRRs = int.from_bytes(dnsPacket.read(2))
    numberofAuthorityRRs = int.from_bytes(dnsPacket.read(2))
    numberofAditionalRRs = int.from_bytes(dnsPacket.read(2))

print("Identification (in Hex): " + "0x" + str(identification)[2:-1].replace("\\x", ""))

QR = int.from_bytes(flag, 'big') >> 15

if QR == 1:
    print("Type: Response")
else: 
    print("Type: Request")

operationCode = int.from_bytes(flag, 'big') >> 8 & 0b01111000

assingedOpCode = False
for code in opCodes.keys(): 
    if code == operationCode:
        assingedOpCode = True
        print(opCodes[code])

if not assingedOpCode: 
    print("Unassinged")


AA = int.from_bytes(flag, 'big') >> 8 & 0b00000100

if AA == 1: 
    print("Authoritative Answer")
else:
    print("Non-authoritative Answer")

TC = int.from_bytes(flag, 'big') >> 8 & 0b00000010

if TC == 1:
    print("Tuncated")

RD = int.from_bytes(flag, 'big') >> 8 & 0b00000001

if RD == 1: 
    print("Recursive Query")
else: 
    print("Iterative Query")

RA = (int.from_bytes(flag, 'big') & 0b10000000) >> 7 

if RA == 1: 
    print("Recursion Available")
else: 
    print("Recursion Unavailable")

rCode = (int.from_bytes(flag, 'big') & 0b00001111) 

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
print("Number of Additional Resource Records: " + str(numberofAditionalRRs))


# binaryFlag = bin(int.from_bytes(flag,"big")) 
# print(binaryFlag[2:10] + " " + binaryFlag[10:18])


