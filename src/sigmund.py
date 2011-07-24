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
import re

class Sigmund():
    
    secret = ""
    random_amount = 102400
    tokenExpiryTime = 300
    
    def generate (self, params):
        
        signature = self.generatePlainSignature(params)
        timestamp = str(int(math.floor(time.time())))
        
        randomNumber = int(math.ceil(random.uniform(1, self.random_amount)))
        salt         = signature + str(randomNumber) + timestamp + str(self.secret)
        
        salt_hash      = self.__hash(salt)
        signature_hash = self.__hash(salt_hash + signature + timestamp)
        
        return salt_hash + signature_hash + str(timestamp)
        
    def validate (self, token, params):
        
        if not (self.__isTokenExpectedFormat(token)):
            return False
        
        salt      = token[0:56]
        signature = token[56:112]
        timestamp = token[112:]
        
        regenerated = self.__hash(salt + self.generatePlainSignature(params) + timestamp)
        
        if (signature == regenerated):
            return True
        
        return False
        
    def generatePlainSignature (self, keyvalues):
        
        parts     = ["%s%s" % (k, v) for k, v in keyvalues.items()]
        return "".join(sorted(parts))
    
    def __hash (self, string):
        return hashlib.sha224(string).hexdigest()
        
    def __isTokenExpectedFormat (self, token):
        
        length = len(token)
        
        # len(sha224 + sha224 + epoch)
        if (length < 122):
            return False
        
        stripHashesFromToken = token[112:]
        
        try:
            timestamp = int(stripHashesFromToken)
        except ValueError:
            return False
        
        expiresAt = time.time() - self.tokenExpiryTime
        
        if timestamp < expiresAt:
            return False
        
        return True
  
  
  
  
  
  
  
  
  