"""
TODO
 - different param types
 - secrets
"""
import unittest
import math
import time
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
        # len(sha1 + sha1 + epoch)
        expectedLength = 112 + len(str(int(math.floor(time.time()))))
        self.assertEquals(expectedLength, len(token), "Token is expected length")
        
        self.assertTrue(
            sigmund.validate(token, testData),
            'can generate a simple token and validate'
        )

if __name__ == "__main__":
    unittest.main()
