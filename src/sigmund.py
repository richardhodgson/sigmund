"""
TODO
 - add time based expiry
 - simple salt and signature positions (based on pieces... max 56/2)
 - rotating secrets (and secrets generation)
 - rotating positions (and position map generation)
"""
import hashlib
import random
import math
import time

class Sigmund():
    
    secret = ""
    random_amount = 102400
    
    def generate (self, params):
        
        signature = self.generatePlainSignature(params)
        timestamp = int(math.floor(time.time()))
        
        randomNumber = int(math.ceil(random.uniform(1, self.random_amount)))
        salt         = signature + str(randomNumber) + str(timestamp) + str(self.secret)
        
        salt_hash      = self.__hash(salt)
        signature_hash = self.__hash(salt_hash + signature)
        
        return salt_hash + signature_hash + str(timestamp)
        
    def validate (self, token, params):
        
        salt = token[0:56]
        signature = token[56:112]
        
        #don't need this yet
        #timestamp = token[112:]
        
        if (signature == self.__hash(salt + self.generatePlainSignature(params))):
            return True
        
        return False
        
    def generatePlainSignature (self, keyvalues):
        
        parts     = ["%s%s" % (k, v) for k, v in keyvalues.items()]
        return "".join(sorted(parts))
    
    def __hash (self, string):
        return hashlib.sha224(string).hexdigest()
  