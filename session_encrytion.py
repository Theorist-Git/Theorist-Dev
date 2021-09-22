from json import JSONEncoder, JSONDecoder, loads, dumps
from zlib import decompress, compress
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin
from Crypto.Cipher import AES
from base64 import b64decode, b64encode


class EncryptedSession(CallbackDict, SessionMixin):

    def __init__(self, initial=None):
        def on_update(self):
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.modified = False


class EncryptedSessionInterface(SessionInterface):
    session_class = EncryptedSession
    compress_threshold = 1024

    def open_session(self, app, request):

        session_cookie = request.cookies.get(app.session_cookie_name)
        if not session_cookie:
            return self.session_class()

        # Get the crypto key
        crypto_key = app.config['SESSION_CRYPTO_KEY']

        # Split the session cookie : <z|u>.<base64 cipher text>.<base64 mac>.<base64 nonce>
        cookie_share = session_cookie.split(".")
        if len(cookie_share) != 4:
            return self.session_class()  # Session cookie not in the right format

        try:
            # Compressed data?
            if cookie_share[0] == 'Confertus':
                is_compressed = True
            else:
                is_compressed = False

            # Decode the cookie parts from base64
            ciphertext = b64decode(bytes(cookie_share[1], 'utf-8'))
            mac = b64decode(bytes(cookie_share[2], 'utf-8'))
            nonce = b64decode(bytes(cookie_share[3], 'utf-8'))

            # Decrypt
            cipher = AES.new(crypto_key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, mac)

            # Convert back to a dict and pass that onto the session
            if is_compressed:
                data = decompress(data)
            session_dict = loads(str(data, 'utf-8'), cls=BinaryAwareJSONDecoder)

            return self.session_class(session_dict)

        except ValueError:
            return self.session_class()

    def save_session(self, app, session, response):

        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)

        if not session:
            if session.modified:
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain,
                                       path=path,
                                       secure=secure,
                                       samesite=samesite)
            return
        expires = self.get_expiration_time(app, session)

        # Decide whether to compress
        bdict = bytes(dumps(dict(session), cls=BinaryAwareJSONEncoder), 'utf-8')
        if len(bdict) > self.compress_threshold:
            prefix = "Confertus"
            bdict = compress(bdict)
        else:
            prefix = "HaudConfertus"

        # Get the crypto key
        crypto_key = app.config['SESSION_CRYPTO_KEY']

        # Encrypt using AES in EAX mode
        cipher = AES.new(crypto_key, AES.MODE_EAX)
        ciphertext, mac = cipher.encrypt_and_digest(bdict)
        nonce = cipher.nonce

        # Convert the ciphertext, mac, and nonce to base64
        b64_ciphertext = b64encode(ciphertext)
        b64_mac = b64encode(mac)
        b64_nonce = b64encode(nonce)

        # Create the session cookie as <u|z>.<base64 cipher text>.<base64 mac>.<base64 nonce>
        FINAL_COOKIE = [prefix, b64_ciphertext.decode(), b64_mac.decode(), b64_nonce.decode()]
        session_cookie = ".".join(FINAL_COOKIE)

        # Set the session cookie
        response.set_cookie(app.session_cookie_name,
                            session_cookie,
                            expires=expires,
                            httponly=True,
                            domain=domain,
                            path=path,
                            secure=secure,
                            samesite=samesite,
                            )


class BinaryAwareJSONEncoder(JSONEncoder):
    """
    Converts a python object, where binary data is converted into an object
    that can be decoded using the BinaryAwareJSONDecoder.
    """

    def default(self, obj):
        if isinstance(obj, bytes):
            return {
                '__type__': 'bytes',
                'b': b64encode(obj).decode()
            }

        else:
            return JSONEncoder.default(self, obj)


class BinaryAwareJSONDecoder(JSONDecoder):
    """
    Converts a json string, where binary data was converted into objects form
    using the BinaryAwareJSONEncoder, back into a python object.
    """

    def __init__(self):
        JSONDecoder.__init__(self, object_hook=self.dict_to_object)

    @staticmethod
    def dict_to_object(d):
        if '__type__' not in d:
            return d

        typ = d.pop('__type__')
        if typ == 'bytes':
            return b64decode(bytes(d['b'], 'utf-8'))
        else:
            # Oops... better put this back together.
            d['__type__'] = typ
            return d
