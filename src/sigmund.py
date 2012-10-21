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
        
        randomNumber = generateRandomNumber(1, self.random_amount)
        salt         = signature + str(randomNumber) + timestamp
        
        salt_hash      = self.__hash(salt)
        signature_hash = self.__generateSignatureHash(params, salt_hash, timestamp)
        
        return self.serialise(salt_hash, signature_hash, str(timestamp))
        
    def validate (self, token, params):
        
        tokenParts = self.unserialise(token)

        salt      = tokenParts[0]
        signature = tokenParts[1]
        timestamp = tokenParts[2]

        if self.__hasTokenExpired(timestamp):
            return False
        
        regenerated = self.__generateSignatureHash(params, salt, timestamp)
        
        if (signature == regenerated):
            return True
        
        return False
        
    def generatePlainSignature (self, keyvalues):
        parts     = ["%s%s" % (k, v) for k, v in keyvalues.items()]
        return "".join(sorted(parts))
    
    def __hash (self, string):
        return hashlib.sha224(string).hexdigest()

    def __hasTokenExpired (self, timestamp):
        try:
            timestamp = int(timestamp)
        except ValueError:
            return False
        
        expiresAt = time.time() - self.tokenExpiryTime
        
        if timestamp < expiresAt:
            return True
        
        return False
        
    def __generateSignatureHash (self, params, salt, timestamp):
        
        plainSignature = self.generatePlainSignature(params)
        secret         = self.secret
        
        if isinstance(secret, list):
            secret = get_rotated_secret(secret, timestamp)
        
        return self.__hash(salt + plainSignature + timestamp + secret)
    
    def serialise (self, salt_hash, signature_hash, timestamp):
        return salt_hash + signature_hash + timestamp

    def unserialise (self, token):

        salt      = token[0:56]
        signature = token[56:112]
        timestamp = token[112:]

        return [salt, signature, timestamp]

def generate_secrets_to_file (path, numberOfSecrets=10):
    """
    Generates a secrets file
    Returns the secrets it wrote to the file
    """
    
    secrets = generate_secrets(numberOfSecrets)

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
    sigmund = Sigmund()

    for i in range(numberOfSecrets):
        secret = sigmund.generate({i: generateRandomNumber(i, 102400)})
        secrets.append(secret)

    return secrets

def load_secrets_from_file (path):

    reader = open(path, 'r')
    contents = reader.read()

    if not contents:
        raise Error("Secrets file at '" + path + "' is empty")
    
    return contents.split(SECRETS_FILE_DELIMITER)

def get_rotated_secret (secrets, timestamp):
        """
        Takes a list of secrets and chooses one depending on timestamp.
        
        Choice is made by dividing a day by number of secrets to create groups.
        The timestamp is checked for the time of day it was created at, which
        is then mapped to the relevant group.
        
        The secret is return for the group that is matched
        
        """
        fullDay = 86400
         
        numberOfSecrets = len(secrets)
        tokenDateTime   = datetime.fromtimestamp(float(timestamp))
        
        tokenSeconds    = ((tokenDateTime.hour-1) * 3600) + (tokenDateTime.minute * 60) + tokenDateTime.second
        partitionSize   = fullDay / numberOfSecrets

        return secrets[tokenSeconds / partitionSize]

def generateRandomNumber (min, max):
    return int(math.ceil(random.uniform(min, max)))

