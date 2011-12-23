"""
TODO
 - simple salt and signature positions (based on pieces... max 56/2)
 - rotating positions (and position map generation)
"""
import hashlib
import random
import math
import time
import re
from datetime import datetime

SECRETS_FILE_DELIMITER = ","

class Sigmund():
    
    secret = ""
    random_amount = 102400
    tokenExpiryTime = 300
    
    def generate (self, params):
        
        signature = self.generatePlainSignature(params)
        timestamp = str(int(math.floor(time.time())))
        
        randomNumber = int(math.ceil(random.uniform(1, self.random_amount)))
        salt         = signature + str(randomNumber) + timestamp
        
        salt_hash      = self.__hash(salt)
        signature_hash = self.__generateSignatureHash(params, salt_hash, timestamp)
        
        return salt_hash + signature_hash + str(timestamp)
        
    def validate (self, token, params):
        
        if not (self.__isTokenExpectedFormat(token)):
            return False
        
        salt      = token[0:56]
        signature = token[56:112]
        timestamp = token[112:]
        
        regenerated = self.__generateSignatureHash(params, salt, timestamp)
        
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
        
    def __generateSignatureHash (self, params, salt, timestamp):
        
        plainSignature = self.generatePlainSignature(params)
        secret         = self.secret
        
        if isinstance(secret, list):
            secret = self.getRotatedSecret(secret, timestamp)
        
        return self.__hash(salt + plainSignature + timestamp + secret)
        
    def getRotatedSecret (self, secrets, timestamp):
        """
        Takes a list of secrets and chooses one depending on timestamp.
        
        Choice is made by dividing a day by number of secrets to create groups.
        The timestamp is checked for the time of day it was created at, which
        is then mapped to the relevant group.
        
        The secret is return for the group that is matched
        
        n.b. I'm sure theres a better way to do this than a loop...
        """
        fullDay = 86400
        
        numberOfSecrets = len(secrets)
        tokenDateTime   = datetime.fromtimestamp(float(timestamp))
        
        tokenSeconds    = (tokenDateTime.hour * 3600) + (tokenDateTime.minute * 60) + tokenDateTime.second
        partitionSize   = fullDay / numberOfSecrets
        
        for group in range(numberOfSecrets):
            if (tokenSeconds < ((group+1) * partitionSize)):
                return secrets[group]

def generate_secrets_to_file (path):
    """
    Generates a secrets file
    Returns the secrets it wrote to the file
    """
    
    secrets = generate_secrets(10)

    writer = open(path, 'w')
    writer.write(SECRETS_FILE_DELIMITER.join(secrets))
    writer.close()
    
    return secrets
    

def generate_secrets (numberOfSecrets):
    """
    Generate random secrets
    Returns a list of secrets
    """

    secrets = []
    timestamp = str(int(math.floor(time.time())))

    for i in range(numberOfSecrets):
        randomNumber = int(math.ceil(random.uniform(i, 102400)))
        secret = hashlib.sha224(str(randomNumber) + timestamp).hexdigest()
        secrets.append(secret)

    return secrets

def load_secrets_from_file (path):

    reader = open(path, 'r')
    contents = reader.read()

    if not contents:
        raise Error("Secrets file at '" + path + "' is empty")
    
    return contents.split(SECRETS_FILE_DELIMITER)
