# AES GCM Mode
### Introduction
This module tries to explain AES GCM mode of encryption with an example. GCM mode is an AEAD mode of encryption and not commonly understood among engineers. This module tries to help folks understand it better by seeing it work. The code is written in python and is fairly well commented.

### Theory
Authenticated encryption with associated data(AEAD) modes of encryption provide 2 security gurantees:  
* Confidenciality: The encrypted data will not leak any information about the secret plaintext data without the correct decryption key
* Integrity: The secret plaintext data and associated data were not modified by an adversary after being encrypted with AES GCM  

In simpler collocial English:  
* Only people who know the secret key can read the information that was encrypted
* The information was not changed by anyone once it was encrypted  

#### Difference from other modes of encryption
The more commonly known modes of encryption CBC, CTR modes don't provide the integrity gurantee that AEAD modes provide. 

### Running the script
#### Dependencies
It requires Python and Pycryptodome<http://pycryptodome.readthedocs.io/en/latest/src/introduction.html>  
You can get Pycryptodome by running "pip install pycryptodome"  
You should do it in a virtual enviorment if you already have pycrypto as it is a fork of pycrypto and they might interfeare with each other in unexpted ways
#### How to run
After you get the dependencies installed and download the file  
From the terminal run - "python aes_gcm.py"  
It will guide you through the whole encryption and decryption process  
