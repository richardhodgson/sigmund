# Sigmund

Sign requests between client and server.

On the client, use `generate()` to create a signature for the keys in `data`.

    import urllib2
    from sigmund import Sigmund

    data = {
        "score" => 2344,
        "playerId" => 57
    }

    sigmund = Sigmund()
    signature = sigmund.generate(data)

    data["signature"] = signature

    urllib2.urlopen("http://example.com/games/3", data)

The server can use the `signature` to verify the `score` and `playerId` values.

    sigmund = Sigmund()

    data = {
        "score" => request.POST['score'],
        "playerId" => request.POST['playerId']
    }

    if not sigmund.validate(request.POST['signature'], data):
        raise Error("Parameters not valid")


Integrity can be improved by specifying a shared `secret`...

    sigmund = Sigmund()
    sigmund.secret = "shhh123"

...or even more by specifying a collection of secrets to rotate between.


    sigmund = Sigmund()
    sigmund.secret = ["blue1", "green3", "red565"]

Helper functions to generate shared secrets to a file...

    import sigmund
    sigmund.generate_secrets_to_file('/path/to/shared/secrets')

...and read from the file.

    import sigmund

    s = sigmund.Sigmund()
    s.secrets = sigmund.load_secrets_from_file('/path/to/shared/secrets')

Tokens can only be used within 5 minutes from when they are issued. The expiry time can be specified in seconds. For example, to allow tokens to be valid for 1 hour:

    s = sigmund.Sigmund()
    s.tokenExpiryTime = 3600

The `Sigmund` class can be subclassed to override the serialised token structure.

    class CustomSigmund(Sigmund):

        def serialise (self, salt, signature, timestamp):
            return signature_hash + "|" + salt_hash + "|" + timestamp

        def unserialise (self, token):

            salt      = token[57:113]
            signature = token[0:56]
            timestamp = token[114:]

            return [salt, signature, timestamp]

The `serialise` method is passed the `salt`, `signature` and `timestamp` and should return a string combining all three. The `unserialise` method will be called with the `token` and expected to return an array of the original parts.

