"""
TODO
 - different param types
 - secrets
"""
import unittest
import math
import time
import os

from sigmund import Sigmund
from sigmund import generate_secrets_to_file
from sigmund import generate_secrets

class SigmundTests(unittest.TestCase):
    
    def testSignatureGeneration (self):
        
        sigmund = Sigmund()
        
        self.assertEquals(
            'blah123',
            sigmund.generatePlainSignature({"blah": 123}),
            'Can generate a simple signature of params'
        )
        
        self.assertEquals(
            'blah123helloworldtestworking',
            sigmund.generatePlainSignature(
                {
                    "blah":  123,
                    "test":  "working",
                    "hello": "world",
                }
            ),
            'Can generate a simple signature of params'
        )
  
    
    def testGenerateToken (self):
        
        sigmund = Sigmund()
        
        testData = {"blah": 123}
        token    = sigmund.generate(testData)
        
        #this might be brittle...
        # len(sha224 + sha224 + epoch)
        expectedLength = 112 + len(str(int(math.floor(time.time()))))
        self.assertEquals(expectedLength, len(token), "Token is expected length")
        
        self.assertTrue(
            sigmund.validate(token, testData),
            'can generate a simple token and validate'
        )
        
    def testTokenValidation (self):
        
        sigmund = Sigmund()
        
        testData = {"blah": 123}
        
        self.assertFalse(
            sigmund.validate(
                "",
                testData
            ),
            'validate fails an empty token'
        )
        
        
        self.assertFalse(
            sigmund.validate(
                '22c8074a4e99305c9afee5129df44bfde7bf7e24dfc7f51d3697af10a151734ace0166779062da40523a037e2e8aa5a03daf5a1c5e4ccb2e131125666',
                testData
            ),
            'validate fails a short token'
        )
        
        token = sigmund.generate(testData)
        
        self.assertFalse(
            sigmund.validate(
                token[:-1],
                testData
            ),
            'validate fails a short known valid token'
        )
        
        self.assertFalse(
            sigmund.validate(
                token + "a",
                testData
            ),
            'validate fails a token with an invalid timestamp at the end'
        )
        
        timestamp5MinutesAgo = int(time.time()) - 270
        
        self.assertFalse(
            sigmund.validate(
                token[112:] + str(timestamp5MinutesAgo),
                testData
            ),
            'validate fails a token older than 5 minutes'
        )
        
        timestamp4andHalfMinutesAgo = int(time.time()) - 270
        
        self.assertFalse(
            sigmund.validate(
                token[112:] + str(timestamp4andHalfMinutesAgo),
                testData
            ),
            'timestamp cannot be altered, used in signature generation'
        )
        
    def testSimpleSecret (self):
        
        sigmund_no_secret     = Sigmund()
        sigmund_secret        = Sigmund()
        sigmund_secret.secret = "blahblah"
        
        testData     = {"blah": 1234}
        token        = sigmund_no_secret.generate(testData)
        token_secret = sigmund_secret.generate(testData)
        
        self.assertFalse(
            sigmund_no_secret.validate(token_secret, testData),
            'cannot validate a token with a secret unless secret is provided'
        )
        
        self.assertFalse(
            sigmund_secret.validate(token, testData),
            'cannot validate a secretless token against an instance with secret provided'
        )
        
        self.assertTrue(
            sigmund_secret.validate(token_secret, testData),
            'can validate a token with a secret'
        )
        
    def testRotatedSecrets (self):
        
        sigmund = Sigmund()
        
        secrets = ['a', 'b', 'c', 'd']
        
        self.assertEquals(
            'a',
            sigmund.getRotatedSecret(secrets, 1),
            '1am hour chooses the first secret'
        )
        
        self.assertEquals(
            'a',
            sigmund.getRotatedSecret(secrets, 3600),
            '2am hour chooses the first secret'
        )
        
        self.assertEquals(
            'b',
            sigmund.getRotatedSecret(secrets, 21600),
            '6am hour chooses the second secret'
        )
        
        self.assertEquals(
            'c',
            sigmund.getRotatedSecret(secrets, 43200),
            '12pm chooses the third secret'
        )
        
        self.assertEquals(
            'd',
            sigmund.getRotatedSecret(secrets, 64800),
            '6pm chooses the final secret'
        )
        
        self.assertEquals(
            'a',
            sigmund.getRotatedSecret(secrets, 86400),
            'midnight chooses the first secret'
        )
        
    def testRotatingSecrets (self):
        
        sigmund = Sigmund()
        
        testData = {"blah": 'test'}
        sigmund.secret = ['a', 'b', 'c', 'd']
        
        token = sigmund.generate(testData)
        
        self.assertTrue(
            sigmund.validate(token, testData),
            'can validate a token against multiple secrets'
        )
        
    def testGenerateSecretsToFile (self):
        
        tmpPath = os.path.join(os.path.dirname(__file__), 'test_secrets')
        tmpFile = os.path.join(tmpPath, 'some_secrets')
        
        if (os.path.isfile(tmpFile)):
            os.unlink(tmpFile)
            
        if (os.path.isdir(tmpPath)):
            os.rmdir(tmpPath)
        
        os.mkdir(tmpPath)
        
        secrets = generate_secrets_to_file(tmpFile)
        
        self.assertTrue(
            os.stat(tmpFile),
            "Secrets file has been created"
        )
        
        generatedFile = open(tmpFile, 'r')
        
        self.assertEquals(
            generatedFile.read(),
            ",".join(secrets),
            "Secrets have been written to the file"
        )
        
        os.unlink(tmpFile)
        os.rmdir(tmpPath)
        
    def testGenerateSecrets (self):

        secrets = generate_secrets(7)

        self.assertEquals(
            len(secrets),
            7,
            "Can generate expected number of secrets"
        )

        self.assertNotEquals(
            secrets[0],
            secrets[1],
            "Generated secrets are different"
        )

        self.assertEquals(
            len(secrets[2]),
            56,
            "Generated secrets are a particular length"
        )

    def testLoadSecretsFromFile (self):
        pass
        

if __name__ == "__main__":
    unittest.main()
