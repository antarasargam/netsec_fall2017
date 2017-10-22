#Server

import asyncio
import playground
import random, zlib, logging
from playground import getConnector
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT16, UINT8, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport

class RequestToBuy(PacketType):
    DEFINITION_IDENTIFIER = "RequestToBuy"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

             ]

class RequestItem(PacketType):
    DEFINITION_IDENTIFIER = "RequestItem"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

             ]

class SendItem(PacketType):
    DEFINITION_IDENTIFIER = "SendItem"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
            ("Item", STRING),
             ]


class RequestMoney(PacketType):
    DEFINITION_IDENTIFIER = "RequestMoney"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Amount", UINT32)
             ]


class SendMoney(PacketType):
    DEFINITION_IDENTIFIER = "SendMoney"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Cash", UINT32)
             ]

class FinishTransaction(PacketType):
    DEFINITION_IDENTIFIER = "FinishTransaction"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

             ]

class PEEPpacket(PacketType):

    DEFINITION_IDENTIFIER = "PEEP.Packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("Type", UINT8),
        ("SequenceNumber", UINT32({Optional: True})),
        ("Checksum", UINT16),
        ("Acknowledgement", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))
         ]

class ShopServerProtocol(asyncio.Protocol):

    serverstate = 0

    def __init__(self, loop):
        self.deserializer = PacketType.Deserializer()
        self.transport = None
        self.loop = loop

    def connection_made(self, transport):
        print("ShopServer connection_made is called")
        self.transport = transport

    def data_received(self, data):
        print("ShopServer Data_received is called")

        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
                print("Inside Data received of Application")

                if isinstance(pkt, RequestToBuy) and self.serverstate == 0:
                    self.serverstate += 1

                    # PACKET 2 - Request Item packet
                    response = RequestItem()

                    print("Sent RequestItem")
                    self.transport.write(response.__serialize__())

                elif isinstance(pkt, SendItem) and self.serverstate == 1:
                    self.serverstate += 1

                    # PACKET 4 - Request Money packet
                    response = RequestMoney()

                    if pkt.Item == "Bread":
                        response.Amount = 4
                    elif pkt.Item == "Butter":
                        response.Amount = 10
                    else:
                        response.Amount = 0

                    print("Sent RequestMoney")
                    self.transport.write(response.__serialize__())

                elif isinstance(pkt, SendMoney) and self.serverstate == 2:
                    self.serverstate += 1

                    # PACKET 6 - Finish Transaction packet
                    response = FinishTransaction()

                    print("Sent FinishTransaction")
                    self.transport.write(response.__serialize__())
                    self.transport.close()

                else:
                    print(pkt.Type)
                    print("Server Received Incorrect Packet. Closing Connection. Try Again!")
                    self.transport.close()


    def connection_lost(self,exc):
        print('\nThe ShopClient sent a connection close to the server')
        self.transport.close()
        self.loop.stop()


class PeepServerTransport(StackingTransport):

    def __init__(self,protocol, transport):
        self.protocol=protocol
        self.exc = None
        self.transport = transport
        super().__init__(self.transport)

    def write(self, data):
        self.protocol.write(data)

    def close(self):
        self.protocol.close()

    def connection_lost(self):
        self.protocol.connection_lost(self.exc)


class PEEPServerProtocol(StackingProtocol):
    serverstate = 0
    clientseq = 0
    serverseq = 0
    # Bunch of class variables
    global_number_seq = 0
    global_number_ack = 0
    global_packet_size = 0
    count_of_function_call = 0
    number_of_packs = 0
    recv_window = {}
    prev_sequence_number = 0
    received_seq_no = 0
    prev_packet_size = 0
    sending_window = {}
    sending_window_count = 0
    global_pig = 0
    keylist1 = []

    def __init__(self, loop):
        self.deserializer = PacketType.Deserializer()
        self.transport = None
        self.loop = loop

    def calculateChecksum(self, instance):
        self.instance = instance
        self.instance.Checksum = 0
        bytes = self.instance.__serialize__()
        return zlib.adler32(bytes) & 0xffff

    def checkChecksum(self, instance):
        self.instance = instance
        pullChecksum = self.instance.Checksum
        self.instance.Checksum = 0
        bytes = self.instance.__serialize__()
        if pullChecksum == zlib.adler32(bytes) & 0xffff:
            return True
        else:
            return False

    def connection_made(self, transport):
        print("\n================== PEEP Server Connection_made Called =========================")
        self.transport = transport


    def data_received(self, data):
        print("\n================== PEEP Server Data_Received called ===========================")
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            # Checksum Check
            # SYN from client
            checkvalue = self.checkChecksum(pkt)
            if pkt.Type == 0 and self.serverstate == 0:
                self.serverstate += 1
                self.clientseq = pkt.SequenceNumber
                if checkvalue == True:
                    print("\nSYN Received. Seq= ", pkt.SequenceNumber, " Ackno=", pkt.Acknowledgement)
                    print(pkt.Data)

                    if pkt.Data == b"Piggy":
                       self.global_pig = 56
                       print(self.global_pig)
                       print("Choosing Piggybacking")
                    else:
                        print ("Choosing Selective")

                    synack = PEEPpacket()
                    synack.Type = 1
                    synack.Acknowledgement = pkt.SequenceNumber + 1
                    self.global_number_ack = synack.Acknowledgement
                    synack.SequenceNumber = random.randint(5000, 9999)
                    if self.global_pig == 56:
                        synack.Data = b"Piggy"
                    self.serverseq = synack.SequenceNumber
                    self.global_number_seq = self.serverseq + 1
                    synack.Checksum = self.calculateChecksum(synack)
                    print("\n================== Sending SYN-ACK =============================================")
                    packs = synack.__serialize__()
                    self.transport.write(packs)


                else:
                    print("Checksum error. Packet Data corrupt.")
                    self.transport.close()

            elif pkt.Type == 2 and self.serverstate == 1 and pkt.SequenceNumber == self.clientseq + 1 and pkt.Acknowledgement == self.serverseq + 1:
                # Data transmission can start
                print("\nACK Received. Seq no=", pkt.SequenceNumber, " Ack no=", pkt.Acknowledgement)

                self.serverstate += 1
                if checkvalue == True:
                    print("\n================== TCP Connection successful! Client OK to send the Data now.============= \n")

                    # calling higher connection made since we have received the ACK

                    peeptransport = PeepServerTransport(self, self.transport)
                    higherTransport = StackingTransport(peeptransport)
                    self.higherProtocol().connection_made(higherTransport)

                else:
                    print("================== Corrupted ACK packet. Please check on client end.===============\n")
                    self.transport.close()

            # Reset packet received
            elif pkt.Type == 5 :

                 if checkvalue:
                    print("================== Got Encapasulated Packet and Deserialized==================")
                    self.global_packet_size = len(pkt.Data)
                    print("The size of packet is:", self.global_packet_size)
                    print("Seq number of incoming packet", pkt.SequenceNumber)
                    print("Ack Number of incoming packet", pkt.Acknowledgement)
                    #self.receive_window(pkt)

                    print (self.global_pig)

                    if self.global_pig != 56 :
                        self.sendack(self.update_ack(pkt.SequenceNumber,self.global_packet_size))

                    print("Calling data received of higher protocol from PEEP")
                    self.higherProtocol().data_received(pkt.Data)

                 else:
                     print("================== Corrupted Data packet. Please check on client end.===============\n")
                     self.transport.close()

            elif pkt.Type == 2:

                #### NEED A STATE INFO SO THAT Handshake packets are not received here.
                if checkvalue:
                    print("ACK Received from the server. Removing data from buffer.")
                    self.pop_sending_window(pkt.Acknowledgement)

            elif pkt.Type == 3 and self.serverstate == 2:
                if checkvalue:
                    print("RIP Received from Client. Sending RIP-ACK.")
                    # RIPack
                    ripack = PEEPpacket()
                    self.exc=0
                    self.serverstate += 1
                    ripack.Type = 4
                    ripack.Acknowledgement = pkt.SequenceNumber + 1
                    ripack.SequenceNumber = 5555
                    calcChecksum = PEEPServerProtocol(self.loop)
                    ripack.Checksum = calcChecksum.calculateChecksum(ripack)
                    ripz = ripack.__serialize__()
                    self.transport.write(ripz)
                else:
                    print("Corrupt RIP packet received. Please check on server end.")

            elif pkt.Type == 4 and self.serverstate == 3:
                if checkvalue:
                    self.serverstate += 1
                    print("RIP-ACK Received from Client. Closing down the connection.\n")
                    self.connection_lost(self.exc)
                else:
                    print("Corrupt RIP-ACK packet received. Please check on server end.")
            else:
                print ("Shait happened")

    def sendack(self, ackno):
        print ("================== Sending ACK ================\n")

        ack = PEEPpacket()
        calcChecksum = PEEPServerProtocol(self.loop)
        ack.Type = 2
        ack.Acknowledgement = ackno
        print ("ACK No:" + str(ack.Acknowledgement))
        # For debugging
        ack.Checksum = calcChecksum.calculateChecksum(ack)
        print ("Server side checksum for ack is",ack.Checksum)
        bytes = ack.__serialize__()
        print(bytes)
        self.transport.write(bytes)

    '''def receive_window(self, pkt):
        self.number_of_packs += 1
        # Assuming 10 as the size for this packet
        if pkt.SequenceNumber == self.global_number_ack:
            self.global_number_ack = self.update_ack(pkt.SequenceNumber, self.global_packet_size)  # It's actually updating the expected Seq Number
            print("Calling data received of higher protocol from PEEP ")
            self.higherProtocol().data_received(pkt.Data)


        elif self.number_of_packs <= 5:
            self.recv_window[pkt.SequenceNumber] = pkt.Data
            sorted(self.recv_window.items())

            for k, v in self.recv_window.items():
                if k == self.global_number_ack:
                    self.higherProtocol().data_received(v)
                    self.global_number_ack = self.update_ack(pkt.SequenceNumber)
                    self.number_of_packs -= 1

        else:
            print("Receive window is full! Please try after some time")
        #sorted(self.recv_window.items())
        #print (self.recv_window[])
        #for k, v in self.recv_window.items():
            #print("printing contents of the buffer")
            #print(k, v)'''



    def calculate_length(self, data):
        self.prev_packet_size = len(data)

    def update_sequence(self, data):
        if self.count_of_function_call == 0:
            self.count_of_function_call = 1
            self.calculate_length(data)
            return self.global_number_seq
        else:
            self.global_number_seq = self.prev_sequence_number + self.prev_packet_size
            # print("new sequence number", self.global_number_seq)
            self.calculate_length(data)
            return self.global_number_seq

    def update_ack(self, received_seq_number, size):
        self.received_seq_number = received_seq_number
        self.global_number_ack = self.received_seq_number + size
        return self.global_number_ack

    def update_sending_window(self, packet):
        self.packet = packet
        self.sending_window_count += 1
        self.key = self.prev_sequence_number + self.prev_packet_size
        self.sending_window[self.key] = self.packet
        for k,v in self.sending_window.items():
            print ("Key is: ",k, "Packet is: ", v)

        #self.sending_window = sorted(self.sending_window.items())
        keylist = list(self.sending_window)
        self.keylist1 = sorted(keylist)
        return self.packet

    def pop_sending_window(self, AckNum):

        self.AckNum = AckNum
        print (" Ack Number is: ", self.AckNum)
        #self.sending_window = OrderedDict(sorted(self.sending_window.items()))
        for key in self.keylist1:
            print ("Key is: ", key)
            if (self.AckNum <= key):
                print("Key value to pop is", key)
                self.sending_window.pop(key)
                print ("Sending window count is",self.sending_window_count)
                self.sending_window_count = self.sending_window_count - 1
            else:
                print (" Popped all packets ")
        self.keylist1 = []
        return

    def write(self, data):
        print ("================== Writing Data down to wire from Server ================\n")
        i = 0
        l = 1
        udata = data
        print("Size of data", len(data))

        while i < len(udata):
            print("Chunk {}".format(l))

            chunk, data = data[:1024], data[1024:]
            Sencap = PEEPpacket()
            calcChecksum = PEEPServerProtocol(self.loop)
            Sencap.Type = 5
            Sencap.SequenceNumber = self.update_sequence(chunk)
            self.prev_sequence_number = Sencap.SequenceNumber
            print ("SEQ No:" + str(Sencap.SequenceNumber))
            Sencap.Acknowledgement = self.global_number_ack
            print ("ACK No:" + str(Sencap.Acknowledgement))
            Sencap.Data = chunk
            # For debugging
            print("data is",chunk)
            print("size of data",len(chunk))
            Sencap.Checksum = calcChecksum.calculateChecksum(Sencap)

            if self.sending_window_count <= 5:
                print (" Entered count ")
                Sencap = self.update_sending_window(Sencap)
                bytes = Sencap.__serialize__()
                i += 1024
                l += 1
                print (" Writing down after filling up the window ")
                self.transport.write(bytes)
            else:
                print (" Sorry, window is full. ")
                i+=1024
                #### Put some return statement to handle this exception. Code shouldn't hang. ###



    def close(self):
        # RIP Packet
        rip = PEEPpacket()
        rip.Type = 3
        rip.Acknowledgement = 0
        rip.SequenceNumber = 6666
        calcChecksum = PEEPServerProtocol(self.loop)
        rip.Checksum = calcChecksum.calculateChecksum(rip)
        ripz = rip.__serialize__()
        self.transport.write(ripz)


    def connection_lost(self,exc):
        print("================== PEEPServer Closing connection ===========\n")
        self.transport.close()
        self.loop.stop()
        self.transport = None



if __name__ == "__main__":

    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance

    logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
    logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

    Serverfactory = StackingProtocolFactory(lambda: PEEPServerProtocol(loop))
    ptConnector= playground.Connector(protocolStack=Serverfactory)

    playground.setConnector("passthrough",ptConnector)

    coro = playground.getConnector('passthrough').create_playground_server(lambda: ShopServerProtocol(loop),8888)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.close()
