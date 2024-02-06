# Just a placeholder, this should be moved to a more appropriate location and contents adapted

import os
import base64

class CryptoBackend():
    def random_hex_string(length):
        return os.urandom(length).hex()
    
    def random_letter_string(length):
        r = os.urandom(length)
        r = bytearray(r)
        for i in range(length):
            if (r[i] & 0b00100000):
                # A-Z, 0-4
                r[i] = ord('A') + (r[i] & 0b00011111)
            else:
                # a-z, 5-9
                r[i] = ord('a') + (r[i] & 0b00011111)
        
        # to A-Z, a-z
        return r.decode('ascii')
        return os.urandom(length).decode('utf-8')
    
    def random_character_string(length):
        # generate a random string of length length with characters A-Z, a-z, 0-9, -, and _
        random_bytes = os.urandom(length) # generates a few bytes more than needed
        # Note: A and a are statistically twice as likely as the other characters
        random_str = base64.b64encode(random_bytes, bytes('-_','utf-8')).decode('utf-8')[:length]
        return random_str