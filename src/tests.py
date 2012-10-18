import unittest
import math
import time
import os

from sigmund import Sigmund
from sigmund import generate_secrets_to_file
from sigmund import generate_secrets
from sigmund import load_secrets_from_file
from sigmund import get_rotated_secret

class SigmundTests(unittest.TestCase):

    tmpPath = os.path.join(os.path.dirname(__file__), 'test_secrets')
    tmpFile = os.path.join(tmpPath, 'some_secrets')
    
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
            get_rotated_secret(secrets, 1),
            '1am hour chooses the first secret'
        )
        
        self.assertEquals(
            'a',
            get_rotated_secret(secrets, 3600),
            '2am hour chooses the first secret'
        )
        
        self.assertEquals(
            'b',
            get_rotated_secret(secrets, 21600),
            '6am hour chooses the second secret'
        )
        
        self.assertEquals(
            'c',
            get_rotated_secret(secrets, 43200),
            '12pm chooses the third secret'
        )
        
        self.assertEquals(
            'd',
            get_rotated_secret(secrets, 64800),
            '6pm chooses the final secret'
        )
        
        self.assertEquals(
            'a',
            get_rotated_secret(secrets, 86400),
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
        
        self.__create_test_secrets_path()

        secrets = generate_secrets_to_file(self.tmpFile)
        
        self.assertTrue(
            os.stat(self.tmpFile),
            "Secrets file has been created"
        )
        
        generatedFile = open(self.tmpFile, 'r')
        
        self.assertEquals(
            generatedFile.read(),
            ",".join(secrets),
            "Secrets have been written to the file"
        )

        self.__remove_test_secrets_path()
        
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

        self.__create_test_secrets_path()
        
        generatedSecrets = generate_secrets_to_file(self.tmpFile)

        secrets = load_secrets_from_file(self.tmpFile)

        self.assertEquals(
            secrets,
            generatedSecrets,
            "Loaded secrets are same as generated ones"
        )

        self.__remove_test_secrets_path()
    
    def testValidatetokenFromGeneratedSecrets (self):

        self.__create_test_secrets_path()

        generatedSecrets = generate_secrets_to_file(self.tmpFile)
        
        sigmund = Sigmund()
        sigmund.secret = load_secrets_from_file(self.tmpFile);

        testData = {"hello": "world"}

        token = sigmund.generate(testData)

        self.assertTrue(
            sigmund.validate(token, testData),
            "Can validate a token with secrets loaded from file"
        )

        self.__remove_test_secrets_path()

    def testSeparateInstances (self):

        s1 = s2 = Sigmund()

        s1.secret = s2.secret = 'abcd'

        testData = {"hello": "world"}

        token = s1.generate(testData)

        self.assertTrue(
            s2.validate(token, testData),
            "token isn't bound to the instance of Sigmund that generated it"
        )
    
    def testSubclassTokenTemplate (self):

        customSigmund = CustomSigmund()
        customSigmund.secret = 'abcd'

        testData = {"hello": "world"}

        token = customSigmund.generate(testData)

        self.assertTrue(
            customSigmund.validate(token, testData),
            "subclasses can override the token template"
        )


    def __create_test_secrets_path (self):
        
        if (os.path.isfile(self.tmpFile)):
            os.unlink(self.tmpFile)
            
        if (os.path.isdir(self.tmpPath)):
            os.rmdir(self.tmpPath)
        
        os.mkdir(self.tmpPath)
    
    def __remove_test_secrets_path (self):
        os.unlink(self.tmpFile)
        os.rmdir(self.tmpPath)

class CustomSigmund(Sigmund):
    """
    Example of how Sigmund could be subclassed and the token template
    can be overriden.
    """

    def serialiseToken (self, salt_hash, signature_hash, timestamp):
        return signature_hash + salt_hash + '====' + timestamp

    def unserialiseToken (self, token):

        salt      = token[56:112]
        signature = token[0:56]
        timestamp = token[116:]

        return [salt, signature, timestamp]

if __name__ == "__main__":
    unittest.main()
