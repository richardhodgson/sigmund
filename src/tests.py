"""
TODO
 - different param types
 - secrets
"""
import unittest
import math
import time
from dateutil.parser import parse
from sigmund import Sigmund

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

if __name__ == "__main__":
    unittest.main()
