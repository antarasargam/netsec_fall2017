import asyncio
import playground
import random
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT16, UINT8, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
import zlib
import sys

class PEEP(PacketType):

    DEFINITION_IDENTIFIER = "PEEP.Packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Type", UINT8),
        ("SequenceNumber", UINT32({Optional: True})),
        ("Checksum", UINT16),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
]


class PeepClientTransport(StackingTransport):

    def __init__(self,protocol,transport):
        self.protocol = protocol
        self.transport = transport
        #super().__init__(self.transport)


    def write(self, data):
        bytes = data.__serialize__()
        #print(self.lowerTransport())
        self.protocol.write(bytes)

    def close(self):
        self.lowerTransport().connection_lost()


class PEEPClient(StackingProtocol):

    def __init__(self):
        self.transport = None
        self.state = 0
        self.length = 10

    def calculateChecksum(self, c):
        self.c = c
        self.c.Checksum = 0
        print(self.c)
        checkbytes = self.c.__serialize__()
        return zlib.adler32(checkbytes) & 0xffff

    def checkChecksum(self, instance):
        self.instance = instance
        pullChecksum = self.instance.Checksum
        instance.Checksum = 0
        bytes = self.instance.__serialize__()
        if pullChecksum == zlib.adler32(bytes) & 0xffff :
            return True
        else:
            return False


    def connection_made(self, transport):
        print("========PEEP Client Connection_made CALLED=========\n")
        self.transport = transport
        self.protocol = self

        if self.state == 0:
            packet = PEEP()
            packet.Type = 0
            packet.SequenceNumber = random.randrange(1, 1000, 1)
            packet.Acknowledgement = 0
            self.state += 1
            print("=============== Sending SYN PACKET ==================\n")
            packet.Checksum = self.calculateChecksum(packet)
            packs = packet.__serialize__()
            print("\n ================ Serialized SYN ==============: \n",packs)
            self.transport.write(packs)


    def data_received(self, data):

        print("=============== PEEP Client Data_Received CALLED =============\n")
        self.deserializer = PacketType.Deserializer()
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            checkvalue = self.checkChecksum(packet)
            if self.state == 1 and packet.Type == 1 and checkvalue == True:
                print("\n========================== SYN-ACK Received. Seqno= ", packet.SequenceNumber, " Ackno=", packet.Acknowledgement)

                #Sending ACK

                ack = PEEP()
                ack.Type = 2
                ack.SequenceNumber = packet.Acknowledgement
                ack.Acknowledgement = packet.SequenceNumber + sys.getsizeof(packet) + 1
                self.state += 1
                ack.Checksum = self.calculateChecksum(ack)
                clientpacketbytes = ack.__serialize__()
                print ("=================== Sending ACK =================\n")
                self.transport.write(clientpacketbytes)

                peeptransport = PeepClientTransport(self, self.transport)
                self.higherProtocol().connection_made(peeptransport)

            else:
                print("======== Incorrect packet received. Closing connection!=========\n")
                self.transport.close()

    def connection_lost(self, exc):
        print ("============== Closing connection ===========\n")
        self.transport.close()


    def write(self,data):
        print ("=================== Writing Data down ================\n")
        self.transport.write(data)
        
        
Clientfactory = StackingProtocolFactory(lambda: PEEPClient())   

