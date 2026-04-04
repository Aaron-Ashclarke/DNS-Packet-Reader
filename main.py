with open('ExamplePacket', "rb") as dnsPacket:
    identification = dnsPacket.read(2)
    flagFirstByte = dnsPacket.read(1)
    flagSecondByte = dnsPacket.read(1)
    numberOfQuestions = dnsPacket.read(2)
    numberofAwnserRRs = dnsPacket.read(2)
    numberofAuthorityRRs = dnsPacket.read(2)
    numberofAditionalRRs = dnsPacket.read(2)

QR = int.from_bytes(flagFirstByte, 'big') >> 15
operationCode = int.from_bytes(flagFirstByte, 'big') & 0b01110000
print(operationCode)
