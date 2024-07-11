# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
import josepy
class KeyStore:
    def __init__(self, path):
        self.path = path
        self.key_store_json = {}
        if not os.path.exists(self.path):
            self.init_keys()
        
        with open(self.path) as user_file:
            self.key_store_json = json.load(user_file)
    
    @classmethod
    def load_jwk_key(cls,json_key):
        return josepy.JWKEC.from_json(json_key).key

    def init_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        jwkec = josepy.JWKEC(key=private_key)
        self.key_store_json["signing"]={}
        self.key_store_json["signing"]["private"]= jwkec.to_json()
        self.store()

    def store(self):
        with open(self.path,"w") as user_file:
            json.dump(self.key_store_json,user_file)

    def get_private_key(self, name):
        if name in self.key_store_json:
            jwkec = josepy.JWKEC.from_json(self.key_store_json[name]["private"])
            return jwkec.key
        else:
            return None
    
    def get_public_key(self, name):
        private_key = self.get_private_key(name)
        if private_key is None:
            return None
        return private_key.public_key()
    
    def get_public_key_json(self, name):
        jwkec = josepy.JWKEC(key=self.get_public_key(name))
        return jwkec.to_json()
    

    