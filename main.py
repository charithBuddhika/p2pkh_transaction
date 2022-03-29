import struct
import base58
import hashlib
import ecdsa
import binascii
import ecdsa.util


#Test Transaction Implementation

#Transaction Builing Block
#__Outer segment _____ Version
#               |_____ Number of Inputs
#__Input segment _____ Previous Tx Hash (reversed)
#               |_____ Previous Output Index
#               |_____ Script Length
#               |_____ ScriptSig
#               |_____ Sequence
#__Outer segment _____ Number of Outputs
#__Output Segment_____ Value
#               |_____ Script Length
#               |_____ ScriptPubKey
#__Outer segment _____ Locktime 

#Elements in the scriptSig
#__PUSHDATA Opcode
#__Signature_____Header
#          |_____Sig Length
#          |_____Integer
#          |_____R Length
#          |_____R
#          |_____Integer
#          |_____S Length
#          |_____S
#__SigHash Code
#__PUSHDATA Opcode
#__Public Key

prv_txid = "f4cb4fd8680a664544105ac6e2db0a0a54b8c6cd3f9ba184c5649d63a98731f2"

user1_wallet_address = "mxXXcgUWymuGWJ3ekk9q3eLr639e7SRNfN"
user1_hashed_pub_key = base58.b58decode_check(user1_wallet_address)[1:]

#WIF-compressed Private Key
user1_pvt_key_WIF = "cT2gHVP6z7wtsGSArVBmmWq4MFEhSMr7ZdhKU7fHh8VRFPHJPE5d"
#Base58Check decoding
first_encode = base58.b58decode_check(user1_pvt_key_WIF)
private_key_full = binascii.hexlify(first_encode)
#Filtering the private key
user1_pvt_key = private_key_full[2:-2]

user1_pub_key = "023cbd69b82698d2c3bb339c75a86cfbafcd20a60fad40e3a526603ec1b39afc96"

user2_wallet_address = "mtXh676GL8mQFWTz2n1Gpcrv4DKm2VMneH"
user2_hashed_pub_key = base58.b58decode_check(user2_wallet_address)[1:]
# user2_pvt_key = "cVzgiqFDjkHmqMTd1Cv3bxNTyEGhgmKG7Dhpb6EzVuM7UmhYWFaJ"
user2_pub_key = "037ec11fecacf6ee4377193e5af93e6e471f6adeabd6c89d5cc45d51aa4994e5dd"


class tx():
    version         = binascii.hexlify(struct.pack("<L", 1))
    tx_in_count     = binascii.hexlify(struct.pack("<B",1))
    tx_in           = {}
    tx_out_count    = binascii.hexlify(struct.pack("<B",2))
    tx_out1         = {}
    tx_out2         = {}
    lock_time       = binascii.hexlify(struct.pack("<L",0))   

def reverse_byte_order(string):
    reversed_order = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))
    return reversed_order

tx_unsigned = tx()
tx_signed = tx()

#unsined Transaction Input
tx_unsigned.tx_in["txouthash"]      = reverse_byte_order(prv_txid).encode()
tx_unsigned.tx_in["tx_in_index"]    = binascii.hexlify(struct.pack("<L",1))
tx_unsigned.tx_in["script"]         = "76a914".encode() + binascii.hexlify(user1_hashed_pub_key) + "88ac".encode()
tx_unsigned.tx_in["script_bytes"]   = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_in["script"]))))
tx_unsigned.tx_in["sequence"]       = "ffffffff".encode()

#unsigned Transaction Output
tx_unsigned.tx_out1["value"]            = binascii.hexlify(struct.pack("<Q", 50000)) #change the value
tx_unsigned.tx_out1["pk_script"]        = "76a914".encode() + binascii.hexlify(user2_hashed_pub_key) + "88ac".encode()
tx_unsigned.tx_out1["pk_script_bytes"]  = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_out1["pk_script"]))))

tx_unsigned.tx_out2["value"]            = binascii.hexlify(struct.pack("<Q", 10000)) #change the value
tx_unsigned.tx_out2["pk_script"]        = "76a914".encode() + binascii.hexlify(user1_hashed_pub_key) + "88ac".encode()
tx_unsigned.tx_out2["pk_script_bytes"]  = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_out2["pk_script"]))))

#Signing Message Template with scriptPubKey of previous Output
#in place of scriptSig
tx_unsigned_string = (

    tx_unsigned.version
    + tx_unsigned.tx_in_count
    + tx_unsigned.tx_in["txouthash"]
    + tx_unsigned.tx_in["tx_in_index"]
    + tx_unsigned.tx_in["script_bytes"]
    + tx_unsigned.tx_in["script"]
    + tx_unsigned.tx_in["sequence"]
    + tx_unsigned.tx_out_count
    + tx_unsigned.tx_out1["value"]
    + tx_unsigned.tx_out1["pk_script_bytes"]
    + tx_unsigned.tx_out1["pk_script"]
    + tx_unsigned.tx_out2["value"]
    + tx_unsigned.tx_out2["pk_script_bytes"]
    + tx_unsigned.tx_out2["pk_script"]
    + tx_unsigned.lock_time
    + binascii.hexlify(struct.pack("<L",1))
)

#Double SHA256 Hashing the Transaction Message before Signing
hashed_tx = hashlib.sha256(hashlib.sha256(tx_unsigned_string).digest()).digest()
# print(hashed_tx)

#Generating the Signature (ECDSA) of the scriptSig
#Derive the signature
user1_pvt_key_bytes = binascii.unhexlify(user1_pvt_key)
signingkey = ecdsa.SigningKey.from_string(user1_pvt_key_bytes,curve=ecdsa.SECP256k1)

sig_bytes = signingkey.sign_digest(hashed_tx,sigencode=ecdsa.util.sigencode_der_canonize)
sig = binascii.hexlify(sig_bytes)

#Complete Transaction

#Signed Transaction Inputs
tx_signed.tx_in["txouthash"] = reverse_byte_order(prv_txid).encode()
tx_signed.tx_in["tx_in_index"] = binascii.hexlify(struct.pack("<L",1))
tx_signed.tx_in["scriptsig"]= hex(len(sig_bytes)).lstrip("0x").encode() + sig + "01".encode() + hex(len(user2_pub_key)).lstrip("0x").encode() + user2_pub_key.encode()
tx_signed.tx_in["script_length"] = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_signed.tx_in["scriptsig"]))))
tx_signed.tx_in["sequence"] = "ffffffff".encode()

#Signed Transaction outputs
tx_signed.tx_out1["value"]            = binascii.hexlify(struct.pack("<Q", 100000)) #change the value
tx_signed.tx_out1["pk_script"]        = "76a914".encode() + binascii.hexlify(user2_hashed_pub_key) + "88ac".encode()
tx_signed.tx_out1["pk_script_bytes"]  = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_out1["pk_script"]))))

tx_signed.tx_out2["value"]            = binascii.hexlify(struct.pack("<Q", 100000)) #change the value
tx_signed.tx_out2["pk_script"]        = "76a914".encode() + binascii.hexlify(user1_hashed_pub_key) + "88ac".encode()
tx_signed.tx_out2["pk_script_bytes"]  = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_out2["pk_script"]))))

#complete signed transaction
tx_signed_string = (
    tx_signed.version
    + tx_signed.tx_in_count
    + tx_signed.tx_in["txouthash"]
    + tx_signed.tx_in["tx_in_index"]
    + tx_signed.tx_in["script_length"]
    + tx_signed.tx_in["scriptsig"]
    + tx_signed.tx_in["sequence"]
    + tx_signed.tx_out_count
    + tx_signed.tx_out1["value"]
    + tx_signed.tx_out1["pk_script_bytes"]
    + tx_signed.tx_out1["pk_script"]
    + tx_signed.tx_out2["value"]
    + tx_signed.tx_out2["pk_script_bytes"]
    + tx_signed.tx_out2["pk_script"]
    + tx_signed.lock_time
    + binascii.hexlify(struct.pack("<L",1))
)

print(tx_signed_string)

# OP_DUP 76
# OP_HASH160 a9
# ba95f413f2ffbb6a06fb023329e6d09063dce7d9
# OP_EQUALVERIFY 88 
# OP_CHECKSIG ac

# privkey = "3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c"
# print(privkey)
# print(privkey.encode("utf-8"))
# print(privkey.encode().decode("utf-8")) 