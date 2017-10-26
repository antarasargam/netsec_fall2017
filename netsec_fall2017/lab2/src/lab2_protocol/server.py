#Server

import asyncio
import playground
import random, zlib, logging
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, UINT16, UINT8, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
#import Queue

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
    t = {}
    n = 0
    global_received_ack = 0
    prev_ack_number = 0
    return_value = 0
    backlog_window = []

    def __init__(self, loop):
        self.deserializer = PEEPpacket.Deserializer()
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

    async def synackx_timeout(self):
        while self.serverstate < 1:
            await asyncio.sleep(1)
            if self.serverstate < 2:
                self.transport.write(self.synackx)

    async def data_timeout(self):
        print("Inside Data Timer")
        packets = list(self.t.values())
        while self.global_received_ack < self.global_number_seq:
            await asyncio.sleep(0.1)
            for each_packet in packets:
                await asyncio.sleep(0.1)
                if self.global_received_ack < self.global_number_seq:
                    if each_packet.packet.SequenceNumber == self.global_received_ack:
                        self.transport.write(each_packet.packet.__serialize__())
                        print("Packet Retransmitted.")

    '''async def data_timeout(self):
        timerpackets = list(self.t.values())
        timerkeys = list(self.t.keys())
        windowpackets = list(self.sending_window.values())
        windowkeys = list(self.sending_window.keys())
        for timerkeys in windowkeys:'''



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
                    self.synackx = synack.__serialize__()
                    self.transport.write(self.synackx)
                    self.ta = Timerx(0.1, self.synackx_timeout, synack)


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
                    self.global_received_ack = pkt.Acknowledgement
                    self.receive_window(pkt)

                    #print (self.global_pig)

                    #if self.global_pig != 56 :
                    #    self.sendack(self.update_ack(pkt.SequenceNumber,self.global_packet_size))

                    print("Calling data received of higher protocol from PEEP")
                    #self.higherProtocol().data_received(pkt.Data)

                 else:
                     print("================== Corrupted Data packet. Please check on client end.===============\n")
                     self.transport.close()

            elif pkt.Type == 2:
                #### NEED A STATE INFO SO THAT Handshake packets are not received here.
                if checkvalue:
                    '''self.return_value = self.check_if_ack_received_before(pkt)
                    if self.return_value == 1:
                        self.prev_ack_number = 0
                    else:'''
                    self.prev_ack_number = pkt.Acknowledgement
                    self.pop_sending_window(pkt.Acknowledgement)
                    print("ACK Received from the client. Removing data from buffer.", pkt.Acknowledgement)
                    #print("prev_ack_number11111111", self.prev_ack_number)
                    #print("2222222222", pkt.Acknowledgement)


                    self.global_received_ack = pkt.Acknowledgement


            elif pkt.Type == 3 and self.serverstate == 2:
                if checkvalue:
                    self.close_timers()
                    print("RIP Received from Client with Seq. No.: ", pkt.SequenceNumber,".  Sending RIP-ACK.")
                    # RIPack
                    ripack = PEEPpacket()
                    self.exc=0
                    self.serverstate += 1
                    ripack.Type = 4
                    ripack.Acknowledgement = self.global_number_ack
                    ripack.SequenceNumber = 0
                    calcChecksum = PEEPServerProtocol(self.loop)
                    ripack.Checksum = calcChecksum.calculateChecksum(ripack)
                    ripz = ripack.__serialize__()
                    self.transport.write(ripz)
                else:
                    print("Corrupt RIP packet received. Please check on server end.")

            elif pkt.Type == 4 and self.serverstate == 3:
                if checkvalue:
                    self.close_timers()
                    self.serverstate += 1
                    print("RIP-ACK Received from Client with Ack. No.:",pkt.Acknowledgement,". Closing down the connection.\n")
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

    def receive_window(self, pkt):
        self.number_of_packs += 1
        self.packet = pkt
        if self.packet.SequenceNumber == self.global_number_ack:
            self.global_number_ack = self.update_ack(self.packet.SequenceNumber, self.global_packet_size)  #It's actually updating the expected Seq Number
            self.sendack(self.update_ack(self.packet.SequenceNumber, self.global_packet_size))
            self.higherProtocol().data_received(self.packet.Data)
            self.check_receive_window()

        elif self.number_of_packs <= 1000:
            # and self.packet.SequenceNumber <= self.global_number_ack + (1024*1000):
            self.recv_window[self.packet.SequenceNumber] = self.packet.Data
            self.sendack(self.global_number_ack)


            '''
            for k, v in self.recv_window.items():
                if k == self.global_number_ack:
                    self.higherProtocol().data_received(v)
                    self.global_number_ack = self.update_ack(self.packet.SequenceNumber, self.global_packet_size)
                    self.number_of_packs -= 1
            '''
        else:
            print ("Receive window is full or the packet has already been received!")
        #sorted(self.recv_window.items())
        #print (self.recv_window[])
        #for k, v in self.recv_window.items():
            #print ("printing contents of the buffer")
             #print (k, v)'''

    def check_receive_window(self):
        sorted_list = []
        sorted_list = self.recv_window.keys()
        for k in sorted_list:
            if k == self.global_number_ack:
                self.packet_to_be_popped = self.recv_window[k]
                self.sendack(self.update_ack(self.packet_to_be_popped.SequenceNumber, self.global_packet_size))
                self.higherProtocol().data_received(self.packet_to_be_popped.Data)
            else:
                return

    '''def check_if_ack_received_before(self, packet):
        keylist = list(self.sending_window)
        self.keylist1 = sorted(keylist)
        if self.prev_ack_number == packet.Acknowledgement:
            print("REceived two acks of the same value")
            print ("333333333333",self.keylist1)
            for key in self.keylist1:

                if key == packet.Acknowledgement:
                    print("found a key that equals the acknow received")
                    packet_to_be_retrans = self.sending_window[self.keylist1[0]]
                    print("So far so goood!")
                    packet_to_be_retrans.Acknowledgment = self.global_number_ack
                    bytes_retrans = packet_to_be_retrans.__serialize__()
                    self.transport.write(bytes_retrans)
                    print("ready to return")
                    return 1'''


    def calculate_length(self, data):
        self.prev_packet_size = len(data)

    def update_sequence(self, data):
        if self.count_of_function_call == 0:
            self.count_of_function_call = 1
            self.calculate_length(data)
            return self.global_number_seq
        #elif data == 'rip':
            #self.global_number_seq = self.prev_sequence_number + self.prev_packet_size
            #return self.global_number_seq
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
        #self.key = self.prev_sequence_number + self.prev_packet_size
        self.key = self.global_number_seq
        self.sending_window[self.key] = self.packet
        #for k,v in self.sending_window.items():
            #print ("Key is: ",k, "Packet is: ", v)

        #self.sending_window = sorted(self.sending_window.items())
        keylist = list(self.sending_window)
        self.keylist1 = sorted(keylist)
        print("###########################################", self.keylist1)
        return self.packet

    def pop_sending_window(self, AckNum):

        self.AckNum = AckNum
        print (" Ack Number is: ", self.AckNum)
        #self.sending_window = OrderedDict(sorted(self.sending_window.items()))
        for key in self.keylist1:
            print ("Key is: ", key)
            print ("Server: keylist", self.keylist1)
            if (self.AckNum > key):
                #Finishing off timers for the packets with ACKs received

                seqs = list(self.t.keys())
                for chabi in seqs:
                    if self.AckNum > chabi:
                        (self.t[chabi]).cancel()
                        self.t.pop(chabi)
                print("server: dicto", self.sending_window.keys())
                print("Key value to pop is", key)
                self.sending_window.pop(key)
                print ("server: dicto post popped",self.sending_window.keys())
                self.keylist1.pop(0)
                self.sending_window_count = self.sending_window_count - 1
                print("Sending window count is", self.sending_window_count)
                if self.sending_window_count <= 100:
                    print("About to pop backlog")
                    if self.backlog_window != []:
                        data_from_BL = self.backlog_window.pop(0)
                        self.encapsulating_packet(data_from_BL)
                        # bug fix...

                    #else:
                #print (" Popped all packets ")
        #self.keylist1 = []
        return

    def write(self, data):
        self.i = 0
        self.l = 1
        udata = data
        while self.i < len(udata):
            # print("Chunk {}". format(l))

            chunk, data = data[:1024], data[1024:]
            self.backlog_window.append(chunk)
            self.i += 1024
            self.l += 1
            if self.sending_window_count <= 100:
                if self.backlog_window != []:
                    print("About to pop backlog in client")
                    data_from_BL = self.backlog_window.pop(0)
                    self.encapsulating_packet(data_from_BL)
        print ("client: length of bl",len(self.backlog_window))


    def encapsulating_packet(self, data_from_BL_1):
        chunk = data_from_BL_1
        #print("server:udata inside encap packet",udata)
        if chunk == b'rip':
            self.rip = PEEPpacket()
            self.rip.Type = 3
            self.rip.Acknowledgement = 0
            self.rip.SequenceNumber = self.update_sequence(chunk)
            calcChecksum = PEEPServerProtocol(self.loop)
            self.rip.Checksum = calcChecksum.calculateChecksum(self.rip)
            self.update_sending_window(self.rip)
            ripbites = self.rip.__serialize__() # :P
            print(" Writing down RIP Packet to wire after updating window ")
            self.transport.write(ripbites)
            self.tz = Timerx(0.1, self.connection_timeout, self.rip)
            self.chabi = self.rip.SequenceNumber
            self.t[self.chabi] = self.tz

        else:
            self.Sencap = PEEPpacket()
            calcChecksum = PEEPServerProtocol(self.loop)
            self.Sencap.Type = 5
            self.Sencap.SequenceNumber = self.update_sequence(chunk)
            self.prev_sequence_number = self.Sencap.SequenceNumber
            print("SEQ No:" + str(self.Sencap.SequenceNumber))
            self.Sencap.Acknowledgement = self.global_number_ack
            print("ACK No:" + str(self.Sencap.Acknowledgement))
            self.Sencap.Data = chunk
            # For debugging
            #print("data is", chunk)
            print("size of data", len(chunk))
            self.Sencap.Checksum = calcChecksum.calculateChecksum(self.Sencap)

            self.Sencap = self.update_sending_window(self.Sencap)
            self.bytes = self.Sencap.__serialize__()
            print(" Writing down to wire after updating window ")
            self.transport.write(self.bytes)
            self.tx = Timerx(0.1, self.data_timeout, self.Sencap)
            self.chabi = self.global_number_seq
            self.t[self.chabi] = self.tx

    '''def empty_sending_window(self):
        while len(self.backlog_window) < 1:
            print("About to pop backlog in client")
            data_from_BL = self.backlog_window.pop(0)
            self.encapsulating_packet(data_from_BL)
        else:
            while len(self.sending_window) < 1:
                print("Backlog Emptied now. Emptying Sending Window.")
                self.close_true = 1
                for k,v in self.sending_window.items():
                    self.bytes = v.__serialize__()
                    self.i += 1024
                    self.l += 1
                    self.transport.write(self.bytes)
                    # Creating timer for each data packet
                    self.timer = PEEPServerProtocol(loop)
                    self.tx = Timerx(0.1, self.data_timeout, v)
                    self.chabi = self.global_number_seq
                    self.t[self.chabi] = self.tx
                    print("Sent packet with Seq. No.", k)
                    self.pop_sending_window(k)'''

    def close_timers(self):
        for k,v in self.t.items():
            print("cancelling timers.")
            v.cancel()

    def close(self):
        # RIP Packet
        #data = 'rip'
        #self.empty_sending_window()
        #self.close_timers()
        '''self.rip = PEEPpacket()
        self.rip.Type = 3
        self.rip.Acknowledgement = 0'''
        Data=b'rip'
        '''self.rip.SequenceNumber = self.update_sequence(self.rip.Data)
        calcChecksum = PEEPServerProtocol(self.loop)
        self.rip.Checksum = calcChecksum.calculateChecksum(self.rip)
        print ("Sending RIP packet with Seq. No.:",self.rip.SequenceNumber," from client")
        #self.backlog_window.append(rip)'''
        self.write(Data)
        #ripz = rip.__serialize__()
        #self.transport.write(ripz)


    def connection_lost(self,exc):
        print("================== PEEPServer Closing connection ===========\n")
        self.transport.close()
        self.loop.stop()
        self.transport = None

    async def connection_timeout(self):
        while self.sending_window_count > 0:
            await asyncio.sleep(0.2)
            if len(self.keylist1) < 3:
                await asyncio.sleep(0.2)
                self.connection_lost(self)


# Timerx Function code block starts here
class Timerx():


    def __init__(self, timeout, callback, packet):
        self._timeout = timeout
        self._callback = callback
        self.packet = packet
        self._task = asyncio.ensure_future(self._job())

    async def _job(self):
        await asyncio.sleep(self._timeout)
        await self._callback()

    def cancel(self):
        self._task.cancel()



loop = asyncio.get_event_loop()


Serverfactory = StackingProtocolFactory(lambda: PEEPServerProtocol(loop))

'''if __name__ == "__main__":

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
    loop.close()'''
