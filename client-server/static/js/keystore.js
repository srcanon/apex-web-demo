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
            }else {
                this._outerKs[this.userId] = this._ks;
            }
            this.initialised = true;
        }
    }
    isInitialised(){
        return this.initialised;
    }
    setClientPublicKey(clientHost,publicKey){
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
            const privateKey = await window.crypto.subtle.importKey("jwk", encodedKey, ECDSA, false, ["sign"]);
            return privateKey;
        }
        return null;
    }
    async getPublicKey(name) {
        if (name in this._ks) {
            const encodedKey = this._ks[name]["publicKey"];
            const publicKey = await window.crypto.subtle.importKey("jwk", encodedKey, ECDSA, false, ["verify"]);
            return publicKey;
        }
        return null;
    }
    async getEncPrivateKey(name) {
        if (name in this._ks) {
            const encodedKey = JSON.parse(this._ks[name]["privateKey"]);
            const privateKey = await window.crypto.subtle.importKey("jwk", encodedKey, RSA, false, ["decrypt", "unwrapKey"]);
            return privateKey;
        }
        return null;
    }
    async getEncPublicKey(name) {
        if (name in this._ks) {
            const encodedKey = JSON.parse(this._ks[name]["publicKey"]);
            const publicKey = await window.crypto.subtle.importKey("jwk", encodedKey, RSA, false, ["encrypt", "wrapKey"]);
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
    
    setPrivateKey(name, key) {
        const innerKs = this;
        window.crypto.subtle.exportKey("jwk", key)
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
    setPublicKey(name, key) {
        const innerKs = this;
        window.crypto.subtle.exportKey("jwk", key)
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
    store() {
        window.localStorage.setItem("keystore",JSON.stringify(this._outerKs));
    }
}
