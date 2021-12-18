from Crypto.PublicKey import ECC as ecc
from ellipticCurve import elipticCurve
from Crypto.Hash import SHA256
from Crypto.Random import random

#Distintos primos posibles dependiendo de la curva
p256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
p384 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
p521 = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

#Distintos ordenes posibles dependiendo de la curva
order_p256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
order_p384 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
order_p521 = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409 

#Distintos puntos generadores posibles dependiendo de la curva
Gx_p256, Gy_p256 = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 , 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
Gx_p384, Gy_p384 = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
Gx_p521, Gy_p521 = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modInv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

import os
if not os.path.exists('.\ejemplo_de_uso*'):
    curve = elipticCurve('P-256')
    curve.exportkeys('ejemplo_de_uso')
print(curve.getPublicKey().curve)


class elgamalECC_Server:

    def __init__(self, **kwargs):
        self.name = kwargs.get('name')
        self.__key = curve.getPrivateKey()
        self.curve = curve.getPrivateKey().curve
        self.__clients = []
        if self.curve == 'NIST P-256':
            self.order = order_p256
            self.G_point = ecc.EccPoint(Gx_p256,Gy_p256)
            self.p = p256
        elif self.curve == 'NIST P-384':
            self.order = order_p384
            self.G_point = ecc.EccPoint(Gx_p384,Gy_p384)
            self.p = p384
        elif self.curve == 'NIST P-521':
            self.order = order_p521
            self.G_point = ecc.EccPoint(Gx_p521,Gy_p521)
            self.p = p521
    
    def sendKey(self):
        return self.__key.public_key
    
    def getPublicPoint(self):
        return self.__key.pointQ

    def decrypt(self, **c):
        new_point = self.__key.d * c.get('M_point')
        m = c.get('cipher') * modInv(int(new_point.x), self.p)
        m = m % self.p
        mssg = m.to_bytes(m.bit_length() +7 // 8, 'little').decode('utf-8')
        print(mssg)
    
    def add_client(self, client):
        self.__clients.append(client)
    
    def recieve_mssg(self, client, **mssg):
        if not client in self.__clients:
            print('Se desconoce la fuente del mensaje')
        print('Desencriptando mensaje')
        self.decrypt(M_point=mssg.get('M_point'),cipher=mssg.get('cipher'))
        
class elgamalECC_Client:

    def __init__(self, server):
        self.server = server
        self.server_key = server.sendKey()
    
    def encrypt(self, m):
        #Elegir k aleatorio rango [1,n-2]
        m_int = int.from_bytes(m.encode('utf-8'), byteorder='little')
        k = random.randrange(1,self.server.order-1)
        M_point, new_point = k * self.server.G_point, k * self.server.getPublicPoint()
        cipher = m_int * int(new_point.x)
        c = {'M_point':M_point,'cipher':cipher}
        print('Mssg sent to server: {cipher}'.format(cipher=c))
        self.server.recieve_mssg(self,M_point=M_point, cipher=cipher)
        



#Ejemplo de uso
server = elgamalECC_Server(name='server1', keyDoc='ejemplo_de_uso-private-key.pem')
client1 = elgamalECC_Client(server)
server.add_client(client1)

mssg = 'Hola server!'

print('Encriptando mensaje')
client1.encrypt(mssg)
