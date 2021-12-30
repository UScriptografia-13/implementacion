from Crypto.PublicKey import ECC as ecc
from ellipticCurve import elipticCurve
from Crypto.Hash import SHA256
from Crypto.Random import random
from datetime import datetime
import elgamallEllipticCurve

#Basado sobre curva eliptica nist-p256
curve = elipticCurve('P-256')

class bank:
    def __init__(self):
        self.__curveKey = curve.getPrivateKey()
        self.p = elgamallEllipticCurve.p256
        self.order = elgamallEllipticCurve.order_p256
        #Calcular P generador como el Q dado
        self.PointQ = self.__curveKey.pointQ
        #Calcular P1 generador
        k1 = random.randrange(1,self.order-1)
        self.Point1 = k1 * self.PointQ
        #Calcular P2 generador
        k2 = random.randrange(1,self.order-1)
        #Comprobar que es distinto k para no basarnos en el mismo punto
        while(k1 == k2):
            k2 = random.randrange(1,self.order-1)
        self.Point2 = k2 * self.PointQ
        #Calcular z exponente privado
        self.__z = random.randrange(1,self.order-1)
        #Calcular puntos derivados de la clave z
        self.ZQ = self.__z * self.PointQ
        self.ZP1 = self.__z * self.Point1
        self.ZP2 = self.__z * self.Point2
        #Iniciar registro de clientes
        self.clients = {}
        #Registro de transacciones activas, 1 a la vez por cliente
        self.transactions = {}
        #Registro de todos los depositos
        self.deposits = {}
        self.black_list = []
    
    def getPublicKey(self):
        key = {
            'P':self.PointQ,
            'P1':self.Point1,
            'P2':self.Point2,
            'Q':self.ZQ,
            'Q1':self.ZP1,
            'Q2':self.ZP2
        }
        return key
    
    def getOrder(self):
        return self.order
    
    def getMod(self):
        return self.p
    
    def customerKeyShared(self, customerID):
        #C = zI' = u1Q1 + Q2
        return self.__z * customerID
    
    def opposite_point(self, point):
        OP = ecc.EccPoint(point.x,-point.y)
        return OP
    
    def keySharedChecking(self, **customerKey):
        #Lo suyo seria poner un regex
        customer_dni = input("Inserte su DNI (Formato 000000000X)")
        hash_value = SHA256.new(int.from_bytes(customer_dni.encode('utf-8'), byteorder='little')).hexdigest()
        if self.clients.get(customerID) != hash_value:
            raise Exception("El DNI proporcionado no coincide con el del dueño de la cuenta")
        bankKey = self.customerKeyShared(customerKey.get('customerId'))
        return bankKey == customerKey.get('sharedKey')
    
    def add_client(self, **client):
        #Si dni en lista negra lanza error
        if client.get('value') in self.black_list:
            raise Exception('Intento de fraude. Usuario fraudulento ha querido volver a ser cliente del banco')
        self.clients[client.get('key')] = client.get('value')
    
    def start_transaction(self, client):
        if self.transactions.get(client):
            raise Exception('Ya hay una transaccion realizada por el cliente, espere a finalizarla para realizar otra')
        w = random.randrange(1, self.order-1)
        self.transactions[client] = w
        #R = wQ
        #S = wI'
        R_point = w * self.PointQ
        S_point = w * client.getPublicKey()
        return R_point, S_point
    
    def signature_Y_calculus(self, **signature):
        return (signature.get('hash')*self.__z + self.transactions.get(signature.get('client'))) % self.p
    
    def verify_deposit(self, **payment):
        #Verificar que el hash calculado es el dado mediante las ecuaciones de y1 e y2
        #Verificar ecuacion y1P1 + y2P2 = h0A + B
        #Verificar yP = hQ + R e yA = hC + S, con los h,C,R,S correspondientes a la firma calculada a partir de los datos de identidad
        #h0 = H(A,B,Im,d)
        h0 = SHA256.new()
        A = payment.get('data').get('Coin').get('A')
        h0.update(A.x)
        h0.update(A.y)
        B = payment.get('data').get('Coin').get('B')
        h0.update(B.x)
        h0.update(B.y)
        Im = payment.get('merchantID')
        h0.update(Im.x)
        h0.update(Im.y)
        d = payment.get('data').get('additional_info').get('date')
        h0.update(int.from_bytes(str(d).encode('utf-8'),byteorder='little'))
        #Calcular primera ecuacion
        y1P1, y2P2 = payment.get('data').get('y_pair').get('y1')*self.Point1,payment.get('data').get('y_pair').get('y2')*self.Point2
        h0A = h0 * A
        #Primera ecuacion por partes
        ec1_left, ec1_right = y1P1 + y2P2, h0A + B
        #Verificar ecuacion se cumple
        is_verified = ec1_left == ec1_right
        #h= H(A,B,C,R,S)
        h = SHA256.new()
        h.update(A.x)
        h.update(A.y)
        h.update(B.x)
        h.update(B.y)
        C = payment.get('data').get('signature').get('C\'')
        h.update(C.x)
        h.update(C.y)
        R = payment.get('data').get('signature').get('R\'')
        h.update(R.x)
        h.update(R.y)
        S = payment.get('data').get('signature').get('S\'')
        h.update(S.x)
        h.update(S.y)
        #Calcular segunda y tercera ecuacion
        y = payment.get('data').get('y\'').get('value')
        hQ,hC = h*self.ZQ, h*C
        ec2_left,ec2_right = y*self.PointQ, hQ + R
        ec3_left,ec3_right = y*A, hC + S
        is_verified = is_verified and ec2_left==ec2_right and ec3_left == ec3_right
        return is_verified
    
    def check_unique_deposit(self, deposit):
        #(A,B):(h0,y1,y2)
        coin = deposit.get('Coin')
        if coin in self.deposits.keys():
            previus_coin_transaction = self.deposits.get(coin)
            is_the_same_coin = deposit.get('y_pair').get('y1')==previus_coin_transaction.get('y_pair').get('y1') and deposit.get('y_pair').get('y2')==previus_coin_transaction.get('y_pair').get('y2') and
            deposit.get('additional_info').get('date')==previus_coin_transaction.get('additional_info').get('date')
            if not is_the_same_coin:
                print("Encontrado dos puntos diferentes que hacen referencia a la misma moneda. Intento de fraude por parte del cliente")
                #Calcular el valor de ambos hashes
                h0, h1 = SHA256.new(), SHA256.new()
                h0.update(coin.get('A').x)
                h0.update(coin.get('A').y)
                h1.update(coin.get('A').x)
                h1.update(coin.get('A').y) 
                h0.update(coin.get('B').x)
                h0.update(coin.get('B').y)
                h1.update(coin.get('B').x)
                h1.update(coin.get('B').y) 
                h0.update(deposit.get('additional_info').get('merchant').x)
                h0.update(deposit.get('additional_info').get('merchant').y)
                h1.update(previus_coin_transaction.get('additional_info').get('merchant').x)
                h1.update(previus_coin_transaction.get('additional_info').get('merchant').y)  
                h0.update(int.from_bytes(str(deposit.get('additional_info').get('date')).encode('utf-8'),byteorder='little'))
                h1.update(int.from_bytes(str(previus_coin_transaction.get('additional_info').get('date')).encode('utf-8'),byteorder='little'))
                increment_h = (h1 - h0) % self.p
                increment_y2 = (previus_coin_transaction.get('y_pair').get('y2')-deposit.get('y_pair').get('y2')) % self.p
                # s = incremento y2 * inversa incremento h mod p
                s = (increment_y2 * elgamallEllipticCurve.modInv(increment_h, self.p)) % self.P
                # A = s*I' -> I' = inversa s * A, I' = I + P2 -> I = I' - P2---> - P2 = (P2.x,-P2.y) 
                Id_pointM = elgamallEllipticCurve(s,self.p)*A
                Customer_identity = Id_pointM + self.opposite_point(self.Point2)
                print("Encontrado cliente estafador")
                #Proceder al bloqueo del cliente en el sistema (eliminar cliente y almacenar el dni hasheado en una lista negra para que no pueda volver a crearse una cuenta)
                value = self.clients.pop(Id_pointM, None)
                self.black_list.append(value)

                problem = {Customer_identity:{'Double_expended_coin':coin}}
                return problem
        self.deposits[coin] = {'y_pair':{'y1':deposit.get('y_pair').get('y1'),'y2':deposit.get('y_pair').get('y2')},
        'additional_info':{'date':deposit.get('additional_info').get('date'),'merchant':deposit.get('additional_info').get('merchant')}}
        return deposit
                


        

class customer:
    def __init__(self, bank):
        self.bank = bank
        self.bank_Key = bank.getPublicKey()
        self.order = bank.getOrder()
        #Calcular u aleatorio
        self.__u = random.randrange(1,self.order-1)
        # I = u*P1
        self.__id = self.__u * self.bank_Key.get('P1')
        # I' = I + P2
        self.modifiedId = self.__id + self.bank_Key.get('P2')
        #Lo suyo seria poner un regex
        customerDocument = input("Inserte su DNI (Formato 000000000X)")
        self.__dni_HASH = SHA256.new(int.from_bytes(customerDocument.encode('utf-8'), byteorder='little')).hexdigest()
        bank.add_client(key=self.modifiedId,value=self.__dni_HASH)

    
    def getPublicKey(self):
        return self.modifiedId
    
    def getMerchantId(self):
        return self.__id
    
    def BankKeyShared(self):
        #C = zI' = u1Q1 + Q2
        c = self.__u * self.bank_Key.get('Q1')
        c += self.bank_Key.get('Q2')
        return c

    def keySharedChecking(self):
        customerKey = self.BankKeyShared()
        return customerKey == self.bank.customerKeyShared(self.modifiedId)

    def withdrawCoin(self):
        R, S = self.bank.start_transaction(self)
        #s escogido debe ser distinto de 1 para no comprometer la identidad del cliente
        self.__s = random.randrange(2,self.order-1)
        self.__t1 = random.randrange(1,self.order-1)
        self.__t2 = random.randrange(1,self.order-1)
        # A = s * I'
        A_point = self.__s*self.getPublicKey()
        # B = t1 * P1 + t2 * P2
        B_point1, B_point2 = self.__t1*self.bank_Key.get('P1'), self.__t2*self.bank_Key.get('P2')
        B_point = B_point1 + B_point2
        #H = hash(A,B,C,R,S), deprecated, compromete el anonimato del cliente, principio fundamental para esta tecnologia
        h = SHA256.new()
        h.update(A_point.x)
        h.update(A_point.y)
        h.update(B_point.x)
        h.update(B_point.y)
        #H pseudo-anonima = hash(A,B,C',R',S')
        u = random.randrange(1,self.order-1)
        #U debe tener inverso mod p; p primo con U < p
        v = random.randrange(1,self.order-1)
        #C' = s * C
        modified_keyShared = s*self.BankKeyShared()
        h.update(modified_keyShared.x)
        h.update(modified_keyShared.y)
        #R' = u * R + v * P
        modified_R1, modified_R2 = u * R, v * self.bank_Key.get('P')
        modified_R = modified_R1 + modified_R2
        h.update(modified_R.x)
        h.update(modified_R.y)
        #S' = s * u * S + v * A
        modified_S1, modified_S2 = (s*u)%self.bank.getMod() * S, v * A
        modified_S = modified_S1 + modified_S2
        h.update(modified_S.x)
        h.update(modified_S.y)
        r = (elgamallEllipticCurve.modInv(u,self.bank.getMod())*h) % self.bank.getMod()
        y = self.send_signature(r)
        is_trusted = self.verify_signature(r_point=R,s_point=S,to_verify=y,signature=r, key_value=self.getPublicKey(), common_key=self.BankKeyShared())
        if not is_trusted:
            raise Exception('La firma dada por el banco no cumple las ecuaciones de verificacion. No se garantiza la autenticidad de la misma')
        #Tras verificarse alterar y tal que y' = u*y +v
        modified_y = (u * y + v) % self.bank.getMod()
        #Debe poder verificar las ecuaciones modificadas
        is_trusted_new_y = self.verify_signature(r_point=modified_R,s_point=modified_S,to_verify=modified_y,signature=h, key_value=A_point, common_key=modified_keyShared)
        if not is_trusted:
            raise Exception('La firma dada por el banco no cumple las ecuaciones de verificacion. No se garantiza la autenticidad de la misma')
        result = {
            'Coin':{'A':A_point,'B':B_point}
            'Signature':{'C\'':modified_keyShared,'R\'':modified_R,'S\'':modified_S}
            'y\'':{'status':'claimed','value':modified_y}
        }
        return result
    

    def send_signature(self, hash_value):
        return self.bank.signature_Y_calculus(client=self,hash=hash_value)
    
    def verify_signature(self,**kwargs):
        #Verificar yP = rQ + R o modificado, y'P = hQ + R'
        #Verificar yI' = rC + S o modificado, y'A = hC' +S'
        y1_product, y2_product = kwargs.get('to_verify')*self.bank_Key.get('P'), kwargs.get('to_verify')*kwargs.get('key_value')
        ec1_product, ec2_product = kwargs.get('signature')*self.bank_Key.get('Q'),kwargs.get('signature')*kwargs.get('common_key')
        ec1, ec2 = ec1_product + kwargs.get('r_point'), ec2_product + kwargs.get('s_point')
        return y1_product==ec1 and y2_product==ec2

    def payment_protocol(self, merchant):
        #Cliente y mercante ambos computan el hash de h0 = H(A,B,Im,d) con d la fecha del pago
        data = self.withdrawCoin()
        merchant_hash = SHA256.new()
        A = data.get('Coin').get('A')
        merchant_hash.update(A.x)
        merchant_hash.update(A.y)
        B = data.get('Coin').get('B')
        merchant_hash.update(B.x)
        merchant_hash.update(B.y)
        Im = merchant.getMerchantId()
        merchant_hash.update(Im.x)
        merchant_hash.update(Im.y)
        d = datetime.now()
        merchant_hash.update(int.from_bytes(str(d).encode('utf-8'),byteorder='little'))
        to_compare_hash = merchant.create_hash_of_payment(coin=data.get('Coin'),datetime=d,hash=merchant_hash)
        #Cliente comprueba que son iguales
        if merchant_hash != to_compare_hash:
            raise Exception('El hash recibido no coincide con el calculado')
        #Se procede a calcular el problema del pago
        #y1 = u1*s*h0 + t1
        #y2 = s*h0 + t2
        y1 = (((self.__u * self.__s)%self.bank.getMod()) * merchant_hash + self.__t1) % self.bank.getMod()
        y2 = (self.__s * merchant_hash + self.__t2) % self.bank.getMod()
        if not merchant.merchant_verify_coin(y1=y1,y2=y2,coin=data.get('Coin'),hash=merchant_hash):
            raise Exception('Los valores y1 e y2 calculados no son validos')
        result = data.copy()
        result['y_pair'] = {'y1':y1,'y2':y2}
        result['additional_info'] = {'date':d, 'merchant':Im}
        return result


    def create_hash_of_payment(self, **data):
        h = SHA256.new()
        A = data.get('coin').get('A')
        h.update(A.x)
        h.update(A.y)
        B = data.get('coin').get('B')
        h.update(B.x)
        h.update(B.y)
        I = self.getMerchantId()
        h.update(I.x)
        h.update(I.y)
        d = data.get('datetime')
        h.update(int.from_bytes(str(d).encode('utf-8'),byteorder='little'))
        #Mercante comprueba que son iguales
        if h != data.get('hash'):
            raise Exception('El hash enviado por el cliente no coincide con el calculado')
        return h

    def merchant_verify_coin(self,**data):
        #Debe verificarse que y1P1 + y2P2 = h0A +B
        y1P1, y2P2 = data.get('y1')*self.bank.getPublicKey().get('P1'),data.get('y2')*self.bank.getPublicKey().get('P2')
        A, B = data.get('coin').get('A'), data.get('coin').get('B')
        h0_product = data.get('hash')*A 
        left_eq, right_eq = y1P1+y2P2,h0_product+B
        return left_eq == right_eq
    
    def deposit_protocol(self, payment):
        if not self.bank.verify_deposit(data=payment, merchantID=self.getMerchantId()):
            raise Exception('El deposito no se ha verificado correctamente')
        #Punto (h0,y1) en recta y1(h) = (u1*s)*h +t1
        #Punto (h0,y2) en recta y2(h) = (s)*h + t2
        #Si es posible calcular el valor de las rectas, es decir, hay 2 transacciones con la misma moneda (A,B)
        #Es posible determinar la identidad del cliente, llegando a conocer s y u, pudiendo identificar su ID al ser calculado como I = uP1, I'=I+P2
        #El banco como entidad puede tomar medidas para evitar dicho fraude
        state = self.bank.check_unique_deposit(payment)
        print(state)














        