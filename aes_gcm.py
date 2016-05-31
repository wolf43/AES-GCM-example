"""This module tries to explain AES GCM mode with an example."""

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Authenticated encryption on a string using AES GCM with both encryption and MAC

# Key generation
kdf_salt = get_random_bytes(16)
default_passphrase = "I!LIKE!IKE!"
user_passphrase = raw_input("SECRET PASSPHRASE INPUT\nYou will need this to decrypt\nDefault: " + str(default_passphrase) + "\nEnter secret passphrase:")
passphrase = user_passphrase or default_passphrase
print "Passphrase used: " + str(passphrase)
key = PBKDF2(passphrase, kdf_salt)
print "AES Encryption Key: " + str(key)

# Sensitive data to encrypt
default_sensitive_data = "Commence attack on 6 June 1944 at the coast of Normandy"
user_sensitive_data = raw_input("\n\nSENSITIVE DATA INPUT\nDefault: " + str(default_sensitive_data) + "\nEnter sensitive data to encrypt:")
sensitive_data = user_sensitive_data or default_sensitive_data
print "Sensitive data encrypted: " + str(sensitive_data)

# Additional data to authenticate - won't be encrypted but will be authenticated
default_aad = "Operation Overlord"
user_aad = raw_input("\n\nAAD INPUT\nThis won't be encrypted but it will be authenticated\nDefault: " + str(default_aad) + "\nEnter associated authenticated data:")
aad = user_aad or default_aad
print "Associated authenticated data: " + str(aad)

# Encrypt using AES GCM
cipher = AES.new(key, AES.MODE_GCM)
cipher.update(aad)
ciphertext, tag = cipher.encrypt_and_digest(sensitive_data)
# Nonce is generated randomly if not provided explicitly
nonce = cipher.nonce

# Print all the components of the message
print "\nCOMPONENTS OF TRANSMITTED MESSAGE"
print "AAD: " + str(aad)
print "Ciphertext: " + str(ciphertext)
print "Authentication tag: " + str(tag)
print "Nonce: " + str(nonce)
print "KDF salt: " + str(kdf_salt)

# Message to transmit/share
transmitted_message = aad, ciphertext, tag, nonce, kdf_salt
print "\nTransmitted message: " + str(transmitted_message)

#
#
#
#
# Decryption step
# The receiver code begins here
print "\n\n\n"
received_msg = transmitted_message
print "Received message: " + str(received_msg)
received_aad, received_ciphertext, received_tag, received_nonce, received_kdf_salt = received_msg

# Generate decryption key from passphrase and salt
decryption_passphrase = raw_input("Enter decryption passphrase:")
decryption_key = PBKDF2(decryption_passphrase, received_kdf_salt)
print "Decryption Key: " + str(decryption_key)

# Validate MAC and decrypt
# If MAC validation fails, ValueError exception will be thrown
cipher = AES.new(decryption_key, AES.MODE_GCM, received_nonce)
cipher.update(received_aad)
try:
    decrypted_data = cipher.decrypt_and_verify(received_ciphertext, received_tag)
    print "\nMAC validated: Data was encrypted by someone with the shared secret passphrase"
    print "All allies have passphrase - SYMMETRIC encryption!!!"
    print "\nAuthenticated AAD: " + str(received_aad)
    print "Decrypted sensitive data: " + str(decrypted_data)
except ValueError as mac_mismatch:
    print "\nMAC validation failed during decryption. No authentication gurantees on this ciphertext"
    print "\nUnauthenticated AAD: " + str(received_aad)
