from Crypto.Cipher import AES
import binascii, os

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authtag = aesCipher.encrypt_and_digest(msg)
    return(ciphertext, aesCipher.nonce, authtag)

def decrypted_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authtag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authtag)
    return plaintext

secretKey = os.urandom(32) # 256-bit random encryption key
print("Encryption Key:", binascii.hexlify(secretKey))

msg = b'Message for AES-256-GCM + Scrypt encryption'
print("Encrypting this text: ", msg)
encryptedMsg = encrypt_AES_GCM(msg, secretKey)
print("Encrypted Message:", {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'aesIV': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2])
})

decryptedMsg = decrypted_AES_GCM(encryptedMsg, secretKey)
print('decrypted Message:', decryptedMsg)

