#Server IP Address 20174.1.666.46

import logging, os, re
import hashlib, struct
from Lab3.packets import PlsHello, PlsData, PlsHandshakeDone, PlsKeyExchange, PlsClose
from playground.network.common.Protocol import StackingProtocol, StackingProtocolFactory, StackingTransport
from .CertFactory import getPrivateKeyForAddr, getRootCert, getCertsForAddr
from playground.common import CipherUtil
from cryptography.hazmat.primitives.asymmetric import padding, utils
from Lab3.packets import BasePacketType
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

backend = default_backend()

class CIPHER_AES128_CTR(object):
    def __init__(self, key, iv):
        cipher = Cipher(AES(key), CTR(iv), backend)
        self.encrypter = cipher.encryptor()
        self.decrypter = cipher.decryptor()
        #self.block_size = 128

    def encrypt(self, data):
        #padder = PKCS7(self.block_size).padder()
        #paddedData = padder.update(data) + padder.finalize()
        #return self.encrypter.update(paddedData) + self.encrypter.finalize()
        return self.encrypter.update(data) #+ self.encrypter.finalize()

    def decrypt(self, data):
        #paddedData = self.decrypter.update(data) + self.encrypter.finalize()
        #unpadder = PKCS7(self.block_size).unpadder()
        #return unpadder.update(paddedData) + unpadder.finalize()
        return self.decrypter.update(data) #+ self.decrypter.finalize()


class MAC_HMAC_SHA1(object):
    MAC_SIZE = 20

    def __init__(self, key):
        self.__key = key
        self.backend = default_backend()

    def mac(self, data):
        mac = hmac.HMAC(self.__key, hashes.SHA1(), self.backend)
        mac.update(data)
        return mac

    def verifyMac(self, data, checkMac):
        mac = self.mac(data)
        return mac == checkMac

class PLSStackingTransport(StackingTransport):
    def __init__(self, protocol, transport):
        self.protocol = protocol
        self.transport = transport
        self.exc = None
        super().__init__(self.transport)

    def write(self, data):
        self.protocol.write(data)

    def close(self):
        self.protocol.close()

    def connection_lost(self):
        self.protocol.connection_lost(self.exc)


class PLSServer(StackingProtocol):

    incoming_cert = []

    def __init__(self):
        self.deserializer = BasePacketType.Deserializer()
        self.transport = None

    def connection_made(self, transport):
        print("##############PLSServer connection made##################")
        self.address, self.port = transport.get_extra_info("sockname")
        self.peerAddress = transport.get_extra_info("peername")[0]
        splitlist = re.split('(.*)\.(.*)\.(.*)\.(.*)', self.address)[1:4]
        self.splitaddr = '.'.join(splitlist)
        self.transport = transport

    def utf8len(self, s):
        return len(s.encode('utf-8'))

    def GetCommonName(self, cert):
        commonNameList = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(commonNameList) != 1: return None
        commonNameAttr = commonNameList[0]
        return commonNameAttr.value

    def validate(self, certificate):
        clientissuer = CipherUtil.getCertIssuer(certificate[0])
        intermediatesubject = CipherUtil.getCertSubject(certificate[1])
        intermediateissuer = CipherUtil.getCertIssuer(certificate[1])

        encodedrootcert = getRootCert()
        rootcert = CipherUtil.getCertFromBytes(encodedrootcert)
        rootsubject = CipherUtil.getCertSubject(rootcert)

        receivedIDCommonName = self.GetCommonName(certificate[0])
        intermediateCommonName = self.GetCommonName(certificate[1])
        rootCommonName = self.GetCommonName(rootcert)

        print(" My address is:- ", self.address)
        print(" Server PeerAddress is:- ", self.peerAddress)

        if self.peerAddress == receivedIDCommonName:    #This hardcoded IP address must the peerAddress
            print("Checked that the peerAddress and the received commmon name in the certificate is the same!")

            splitlist = re.split('(.*)\.(.*)\.(.*)\.(.*)', self.peerAddress)[1:4]
            FirstThreeOctets = '.'.join(splitlist)

            if clientissuer == intermediatesubject and FirstThreeOctets == intermediateCommonName:
                print("Chain 1 verification succeeded! Going to Check Signature now")
                #checking signature first stage

                signature = certificate[0].signature
                intermediate_pubkey = certificate[1].public_key()
                cert_bytes = certificate[0].tbs_certificate_bytes
                try :
                    intermediate_pubkey.verify(
                    signature,
                    cert_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256())

                    print("Signature check stage 1 successful!")

                    splitlist = re.split('(.*)\.(.*)\.(.*)', FirstThreeOctets)[1:3]
                    FirstTwoOctets = '.'.join(splitlist)

                    if intermediateissuer == rootsubject and FirstTwoOctets == rootCommonName:
                        print("Chain 2 verification succeeded! Going to check signature now")
                        #checking signature second stage

                        signature = certificate[1].signature
                        cert_bytes = certificate[1].tbs_certificate_bytes
                        root_pubkey = rootcert.public_key()

                        try:
                            root_pubkey.verify(
                                signature,
                                cert_bytes,
                                padding.PKCS1v15(),
                                hashes.SHA256())

                            print("Signature check stage 2 successful!")

                            print("FULLY VALIDATED! AWESOME!")

                            return True

                        except Exception:
                            print("Signature check stage 2 failed")
                            raise

                    else:
                        print("Chain 2 verification failed! Check the chain please.")

                except Exception:
                    print("Signature check stage 1 failed")
                    raise

            else:
                print("Chain 1 verification failed! Check the chain please.")

        else:
            print("Peer Address and the address received in the certificate is incorrect! Please check the Identity Certificate")


    def data_received(self, data):
        print("####################SSL layer data received called!#####################")
        self.deserializer.update(data)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, PlsHello):
                self.incoming_cert.append(CipherUtil.getCertFromBytes(packet.Certs[0]))
                self.incoming_cert.append(CipherUtil.getCertFromBytes(packet.Certs[1]))
                self.incoming_cert.append(CipherUtil.getCertFromBytes(packet.Certs[2]))
                print("\nReceived Client Hello packet. Beginning Validation.")
                if self.validate(self.incoming_cert):
                    self.nc = packet.Nonce
                    self.m = hashlib.sha1()
                    self.m.update(packet.__serialize__())
                    print("Certificate Validated. Sending Server hello!\n")
                    self.clientnonce = packet.Nonce
                    serverhello = PlsHello()
                    serverhello.Nonce = int.from_bytes(os.urandom(8), byteorder='big') #12345678
                    self.ns = serverhello.Nonce
                    idcert = getCertsForAddr(self.address)
                    intermediatecert = getCertsForAddr(self.splitaddr)
                    root = getRootCert()
                    serverhello.Certs = []
                    serverhello.Certs.append(idcert)
                    serverhello.Certs.append(intermediatecert)
                    serverhello.Certs.append(root)
                    srvhello = serverhello.__serialize__()
                    print("Sent Server Hello!\n")
                    self.m.update(srvhello)
                    self.transport.write(srvhello)

            if isinstance(packet, PlsKeyExchange):
                print("Received Client Key Exchange. Server Server Keys\n\n")
                self.m.update(packet.__serialize__())
                myprivatekey = getPrivateKeyForAddr(self.address)
                serverpriv = CipherUtil.getPrivateKeyFromPemBytes(myprivatekey)
                decrypted = serverpriv.decrypt(packet.PreKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(), label=None))
                #print("Decrypted Pre-Master Secret: ", decrypted)
                self.pkc = decrypted #int.from_bytes(decrypted, byteorder='big')
                #====================================
                #Creating Server Pre-Master
                serverkey = PlsKeyExchange()
                randomvalue = os.urandom(16) #b'1234567887654321'
                self.pks = randomvalue #int.from_bytes(randomvalue, byteorder='big')
                serverkey.NoncePlusOne = self.clientnonce + 1
                pub_key = self.incoming_cert[0].public_key()
                encrypted = pub_key.encrypt(randomvalue, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(), label=None))
                #print("Encrypted String is: ", encrypted)
                serverkey.PreKey = encrypted
                skey = serverkey.__serialize__()
                print("Sent the Prekey to Client.\n\n")
                self.m.update(skey)
                self.transport.write(skey)

            if isinstance(packet, PlsHandshakeDone):
                print("Received Client Handshake done message.")
                clientdigest = packet.ValidationHash
                serverdigest = self.m.digest()
                #print("Hash digest is: ", serverdigest)
                hdone = PlsHandshakeDone()
                hdone.ValidationHash = serverdigest
                if (serverdigest == clientdigest):
                    print("Digest verification done!")
                    # calling higher connection made since we have received the ACK
                    self.key_generator()
                    plstransport = PLSStackingTransport(self, self.transport)
                    higherTransport = StackingTransport(plstransport)
                    self.higherProtocol().connection_made(higherTransport)
                hdone_s = hdone.__serialize__()
                self.transport.write(hdone_s)

            if isinstance(packet, PlsData):
                print("##################Recieved Data Packet from PLSClient###########################")
                self.ctr = 0
                if self.mac_verification_engine(packet.Ciphertext, packet.Mac):
                    DecryptedPacket = self.decryption_engine(packet.Ciphertext)
                    self.higherProtocol().data_received(DecryptedPacket)

                    self.ctr = 0

                else:
                    self.ctr += 1

                    if self.ctr != 5:
                        print("Verification Failed. Try Again. Failed {}".format(self.ctr))
                        #Incorrect handling here. The control must be go to the other side send the packet again for verification

                    else:
                        print("Verification failed 5 times. Killing Connection and Sending PlsClose.")
                        self.ctr = 0
                        #Creating and Sending PlsClose
                        Close = PlsClose()
                        Close.Error = "Closing Connection due to 5 Verification failures. Aggrresive Close"
                        serializeClose = Close.__serialize__()
                        self.transport.write(serializeClose)
                        self.transport.close()

            if isinstance(packet, PlsClose):
                print("######################Received PlsClose from Client######################### ")
                print(packet.Error)
                self.transport.close()


    def key_generator(self):
        #print("\n\nIn key_generator")
        self.block0 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        self.block0.update(b"PLS1.0")
        self.block0.update(self.nc.to_bytes(8,byteorder="big"))
        self.block0.update(self.ns.to_bytes(8,byteorder="big"))
        self.block0.update(self.pkc)
        self.block0.update(self.pks)
        self.block0_digest = self.block0.finalize()
        #print("Block 0 digest is: ", self.block0_digest)
        block1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        block1.update(self.block0_digest)
        block1digest = block1.finalize()
        #print("Block 1 digest is: ", block1digest)
        block2 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        block2.update(block1digest)
        block2digest =  block2.finalize()
        #print("Block 2 digest is: ", block2digest)
        block3 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        block3.update(block2digest)
        block3digest =  block3.finalize()
        #print("Block 3 digest is: ", block3digest)
        block4 = hashes.Hash(hashes.SHA1(), backend=default_backend())
        block4.update(block3digest)
        block4digest =  block4.finalize()
        #print("Block 4 digest is: ", block4digest)
        #print("Block 0 digest decoded is: ", self.block0_digest.hex())
        #print("Block 1 digest decoded is: ", block1digest.hex())
        #print("Block 2 digest decoded is: ", block2digest.hex())
        #print("Block 1 digest decoded is: ", block3digest.hex())
        #print("Block 1 digest decoded is: ", block4digest.hex())

        concatenated = (self.block0_digest + block1digest + block2digest + block3digest + block4digest)
        print("-----------------------------------------------------------",concatenated)
        # print("Concatenated string is: ", concatenated)
        # print("Concatenated string size is: ", self.utf8len(concatenated),"bytes")
        #binary_string = bin(int(concatenated, 16))[2:]
        # print("Value of concatenated string in bits is: ", binary_string)

        self.ekc = concatenated[:16]
        self.eks = concatenated[16:32]
        self.ivc = concatenated[32:48]
        self.ivs = concatenated[48:64]
        self.mkc = concatenated[64:80]
        self.mks = concatenated[80:96]
        self.encryption = CIPHER_AES128_CTR(self.eks, self.ivs)
        self.decryption = CIPHER_AES128_CTR(self.ekc, self.ivc)

        '''
        concatenated = (self.block0_digest + block1digest + block2digest + block3digest + block4digest).hex()
        #print("Concatenated string is: ", concatenated)
        #print("Concatenated string size is: ", self.utf8len(concatenated),"bytes")
        binary_string = bin(int(concatenated, 16))[2:]
        #print("Value of concatenated string in bits is: ", binary_string)

        self.ekc = binary_string[:128]
        self.eks = binary_string[128:256]
        self.ivc = binary_string[256:384]
        self.ivs = binary_string[384:512]
        self.mkc = binary_string[512:640]
        self.mks = binary_string[640:768]

        self.ekc = bytes(int(self.ekc[i: i + 8], 2) for i in range(0, len(self.ekc), 8))
        self.eks = bytes(int(self.eks[i: i + 8], 2) for i in range(0, len(self.eks), 8))
        self.ivc = bytes(int(self.ivc[i: i + 8], 2) for i in range(0, len(self.ivc), 8))
        self.ivs = bytes(int(self.ivs[i: i + 8], 2) for i in range(0, len(self.ivs), 8))
        self.mkc = bytes(int(self.mkc[i: i + 8], 2) for i in range(0, len(self.mkc), 8))
        self.mks = bytes(int(self.mks[i: i + 8], 2) for i in range(0, len(self.mks), 8))
        '''

    def encryption_engine(self, plaintext):
        #MakeCipher = CIPHER_AES128_CTR(self.eks, self.ivs)
        Ciphertext = self.encryption.encrypt(plaintext)
        self.mac_engine(Ciphertext)

    def decryption_engine(self, ReceivedCiphertext):
        #MakePlaintext = CIPHER_AES128_CTR(self.ekc, self.ivc)
        Plaintext = self.decryption.decrypt(ReceivedCiphertext)
        return Plaintext

    def mac_engine(self, ciphertext):
        mac= hmac.HMAC(self.mks, hashes.SHA1(), backend=default_backend())
        mac.update(ciphertext)

        # Creating PLS Data Packet and Writing down PEEP
        serverdata = PlsData()
        serverdata.Ciphertext = ciphertext
        serverdata.Mac = mac.finalize()
        serializeddata = serverdata.__serialize__()
        self.transport.write(serializeddata)

    def mac_verification_engine(self, ReceivedCiphertext, ReceivedMac):
        mac = hmac.HMAC(self.mkc, hashes.SHA1(), backend=default_backend())
        mac.update(ReceivedCiphertext)
        try :
            mac.verify(ReceivedMac)
            print("Mac Verification Succeeded")
            return True

        except InvalidSignature :
            print("Mac Verification Failed. Invalid Signature")
            raise

    def write(self, data):
        self.encryption_engine(data)

    def close(self):
        print("###########################A Close has been called from higher layer. Sending PlsClose now##########################")
        Close = PlsClose()
        serializeClose = Close.__serialize__()
        self.transport.write(serializeClose)

    def connection_lost(self,exc):
        self.transport.close()
        self.transport = None

#Serverfactorypls = StackingProtocolFactory(lambda: PLSServer())


'''if __name__ == "__main__":

    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance

    #logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
    #logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

    coro = playground.getConnector().create_playground_server(lambda: PLSServer(),8888)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.close()'''

