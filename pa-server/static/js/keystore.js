// SPDX-License-Identifier: Apache-2.0 
// Copyright 2024 REDACTED FOR REVIEW
const RSA = {
    name: "RSA-OAEP",
    hash: "SHA-256"
}
class KeyStore {
    constructor(userId) {
        this._ks = {};
        this._outerKs = {};
        this.userId = userId;
        this.store = this.store.bind(this);
        this.initialised = false;
        if (window.localStorage.getItem("keystore") != null) {
            this._outerKs = JSON.parse(window.localStorage.getItem("keystore"));
            if(this.userId in this._outerKs){
                this._ks = this._outerKs[this.userId];
                this.initialised = true;
            }else {
                this._outerKs[this.userId] = this._ks;
            }
            
        }
    }
    isInitialised(){
        return this.initialised;
    }
    setClientPublicKey(clientHost,publicKey){
        console.log("Setting client public key:" + clientHost + ":" + publicKey);
        if(!("clientPublicKeys" in this._ks)){
            this._ks["clientPublicKeys"]={};
        }
        this._ks["clientPublicKeys"][clientHost]=publicKey;
        this.store();
    }
    getClientPublicKey(clientHost){
        if("clientPublicKeys" in this._ks && clientHost in this._ks["clientPublicKeys"]){
            return this._ks["clientPublicKeys"][clientHost]
        }
        return null;
    }
    async getPrivateKey(name) {
        if (name in this._ks) {
            const encodedKey = JSON.parse(this._ks[name]["privateKey"]);
            const privateKey = await window.crypto.subtle.importKey("jwk", encodedKey, ECDSA, true, ["sign"]);
            return privateKey;
        }
        return null;
    }
    async getPublicKey(name) {
        if (name in this._ks) {
            const encodedKey = JSON.parse(this._ks[name]["publicKey"]);
            const publicKey = await window.crypto.subtle.importKey("jwk", encodedKey, ECDSA, true, ["verify"]);
            return publicKey;
        }
        return null;
    }
    async getEncPrivateKey(name) {
        if (name in this._ks) {
            const encodedKey = JSON.parse(this._ks[name]["privateKey"]);
            const privateKey = await window.crypto.subtle.importKey("jwk", encodedKey, RSA, true, ["decrypt", "unwrapKey"]);
            return privateKey;
        }
        return null;
    }
    async getEncPublicKey(name) {
        if (name in this._ks) {
            const encodedKey = JSON.parse(this._ks[name]["publicKey"]);
            const publicKey = await window.crypto.subtle.importKey("jwk", encodedKey, RSA, true, ["encrypt", "wrapKey"]);
            return publicKey;
        }
        return null;
    }
    getEncodedPublicKey(name){
        if (name in this._ks) {
            return this._ks[name]["publicKey"];
        }
        return null;
    }
    
    async setPrivateKey(name, key) {
        const innerKs = this;
        await window.crypto.subtle.exportKey("jwk", key)
            .then(function (encodedKey) {
                if (!(name in innerKs._ks)){
                    innerKs._ks[name] = {};
                }
                innerKs._ks[name]["privateKey"] = JSON.stringify(encodedKey);
                innerKs.store();
            })
            .catch(function (error) {
                console.log("Error saving private key:" + error);
            })
    }
    async setPublicKey(name, key) {
        const innerKs = this;
        await window.crypto.subtle.exportKey("jwk", key)
            .then(function (encodedKey) {
                if (!(name in innerKs._ks)){
                    innerKs._ks[name] = {};
                }
                innerKs._ks[name]["publicKey"] = JSON.stringify(encodedKey);
                innerKs.store();
            })
            .catch(function (error) {
                console.log("Error saving public key:" + error);
            });
    }
    setClientPublicKeySignature(signature){
        this._ks["publicKeySignature"]=signature;
        this.store();
    }
    getClientPublicKeySignature(){
        return this._ks["publicKeySignature"];
    }
    store() {
        window.localStorage.setItem("keystore",JSON.stringify(this._outerKs));
    }
}
