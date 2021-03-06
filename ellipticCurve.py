from Crypto.PublicKey import ECC as ecc
from Crypto.Hash import SHA256
from Crypto.IO import PKCS8

class elipticCurve:
    def __init__(self, type):
        self.__key = ecc.generate(curve=type)
    
    def exportkeys(self, doc):
        f = open('{d}-private-key.pem'.format(d=doc),'wt')
        #pas = input('Introduce contraseña para la clave: ')
        #f.write(self.__key.export_key(format='PEM', passphrase=pas, use_pkcs8=True,protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"))
        f.write(self.__key.export_key(format='PEM'))
        f.close()
        f = open('{d}-public-key.pem'.format(d=doc),'wt')
        f.write(self.__key.public_key().export_key(format='PEM'))
        f.close()
    
    def importKey(self, doc):
        f = open(doc,'rt')
        self.__key = ecc.import_key(f.read())
    
    def getPrivateKey(self):
        return self.__key

    def getPublicKey(self):
        return self.__key.public_key()


types = ['P-256','P-384','P-521']
import argparse
parser = argparse.ArgumentParser(description='Generate eliptic Curve key')
parser.add_argument('-t','--type',choices=types, help='Type of eliptic curve that will generate', default='P-256')
group = parser.add_mutually_exclusive_group()
group.add_argument('-o','--output', help='Store the key in the document specified')
group.add_argument('-iK','--import_key', help='Import the key spefecified in the doc')
args = parser.parse_args()

if __name__ == '__main__':
    curve = elipticCurve(args.type)
    if (args.output):
        curve.exportkeys(args.output)
        print('Key generated succesfully!')
        print('Key exported to {d}-private-key'.format(d=args.output))
    elif (args.import_key):
        curve.importKey(args.import_key)
        print('Key imported:\n{k}'.format(k=curve.getKey()))
    else:
        print('Key generated succesfully!')
        print('Public key:')
        print(curve.getPublicKey())
        print('Private Key:')
        print(curve.getPrivateKey())
