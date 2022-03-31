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

prv_txid = "067430736273cd3aed01caf527bce386f818e09fffdccb253f41cef24f704b4a"

user1_wallet_address = "mqsMgAqK1oix2hYvktBC7zAYKZnrSa7Tyc"
user1_hashed_pub_key = base58.b58decode_check(user1_wallet_address)[1:]

#WIF-compressed Private Key
user1_pvt_key_WIF = "cPTZaFqegDdCYoVBa4trRNJ9AFvi4LCiwzJWJtiAN2GKSNDvNeGj"
#Base58Check decoding
first_encode = base58.b58decode_check(user1_pvt_key_WIF)
private_key_full = binascii.hexlify(first_encode)
#Filtering the private key
user1_pvt_key = private_key_full[2:-2]

user1_pub_key = "03996642f7a5373f41d9810ce18e67e85d071072b04b39d230300e62a3e74e1cc5"

user2_wallet_address = "mweNjzbqXStYmCoGer7vzVZA6npaPLFDVc"
user2_hashed_pub_key = base58.b58decode_check(user2_wallet_address)[1:]
user2_pub_key = "036b7cca87c766801651c22a5f71b8f3fbda16928179e7110da15ef113a5e53d7a"


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
tx_unsigned.tx_out1["value"]            = binascii.hexlify(struct.pack("<Q", 1000)) #change the value 0.00010
tx_unsigned.tx_out1["pk_script"]        = "76a914".encode() + binascii.hexlify(user2_hashed_pub_key) + "88ac".encode()
tx_unsigned.tx_out1["pk_script_bytes"]  = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_out1["pk_script"]))))

tx_unsigned.tx_out2["value"]            = binascii.hexlify(struct.pack("<Q", 200)) #change the value 0.00003
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
hashed_tx = hashlib.sha256(hashlib.sha256(binascii.unhexlify(tx_unsigned_string)).digest()).digest()

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
tx_signed.tx_in["scriptsig"]= hex(len(sig_bytes+binascii.unhexlify("01".encode()))).lstrip("0x").encode() + sig + "01".encode() + hex(len(binascii.unhexlify(user1_pub_key))).lstrip("0x").encode() + user1_pub_key.encode()
tx_signed.tx_in["script_length"] = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_signed.tx_in["scriptsig"]))))
tx_signed.tx_in["sequence"] = "ffffffff".encode()

#Signed Transaction outputs
tx_signed.tx_out1["value"]            = binascii.hexlify(struct.pack("<Q", 1000)) #change the value
tx_signed.tx_out1["pk_script"]        = "76a914".encode() + binascii.hexlify(user2_hashed_pub_key) + "88ac".encode()
tx_signed.tx_out1["pk_script_bytes"]  = binascii.hexlify(struct.pack("<B", len(binascii.unhexlify(tx_unsigned.tx_out1["pk_script"]))))

tx_signed.tx_out2["value"]            = binascii.hexlify(struct.pack("<Q", 200)) #change the value
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

print("Complete Tx")
print(tx_signed_string)

# OP_DUP 76
# OP_HASH160 a9
# ba95f413f2ffbb6a06fb023329e6d09063dce7d9
# OP_EQUALVERIFY 88 
# OP_CHECKSIG ac

#Decoding

#pre hash image
# 01000000
# 01
# 9f175c7610ab77f89b853f89e8a7109e18ec7948426d1337a34e197cd24b66e1
# 01000000
# 19
# 76a9 14 ba95f413f2ffbb6a06fb023329e6d09063dce7d9 88ac 
# ffffffff
# 02
# e803000000000000
# 19
# 76a9 14 8ebd5b99ff92f2a6c246794f03ff38a5d6630377 88ac 
# c800000000000000
# 19
# 76a9 14 ba95f413f2ffbb6a06fb023329e6d09063dce7d9 88ac
# 00000000
# 01000000

#complete tx
# 01000000
# 01
# 9f175c7610ab77f89b853f89e8a7109e18ec7948426d1337a34e197cd24b66e1
# 01000000
# 6a
#     46
#     3044022018fad1b4ba8c27771c1f715de48b128b6fa293b0be4614f3c21f35c61bfc6ffd02206cee0aa7888ca315c67db9065f17d8c287efddd4abfcdbe7b74112c105570117 
#     01 
#     21 
#     037ec11fecacf6ee4377193e5af93e6e471f6adeabd6c89d5cc45d51aa4994e5dd
# ffffffff
# 02
# e803000000000000
# 19
# 76a9 14 8ebd5b99ff92f2a6c246794f03ff38a5d6630377 88ac
# c800000000000000
# 19
# 76a9 14 ba95f413f2ffbb6a06fb023329e6d09063dce7d9 88ac 
# 00000000

# 0100000001ecda02d42fb658438f673c25b9c7c2b12bca1d06e0bfd5f0a3f6a7ece35848fe010000006b473045022100eb23256876a0542a8ce71c2c67bf1c4525aa1b5eddd01db3d339c108720b6b7402201ecb1c9f8ca7e1090d9faba15cdec5f55e40b9fbf03bdcf24342c8d11c252c330121037e
# c11fecacf6ee4377193e5af93e6e471f6adeabd6c89d5cc45d51aa4994e5ddffffffff02e8030000000000001976a9148ebd5b99ff92f2a6c246794f03ff38a5d663037788acc8000000000000001976a914ba95f413f2ffbb6a06fb023329e6d09063dce7d988ac00000000


##############
# 01 00 00 00
# 01
# 4a4b704ff2ce413f25cbdcff9fe018f886e3bc27f5ca01ed3acd736273307406
# 01 00 00 00
# 6a
#     46
#         30
#         44
#         02
#         20
#         6c967f0e06170b9fccd1194f3d3a015f7fc24ac4edc697436a1c87a15de60b5d
#         02
#         20
#         0988b6f782fa34da2d507925b3b6ad19eacdb7bf87f6246e225d2a4e78175ebc
#         01
#     21
#     03996642f7a5373f41d9810ce18e67e85d071072b04b39d230300e62a3e74e1cc5
# ffffffff
# 02
# e803000000000000
# 19
# 76a9 14 b0e954f0ea07278c7497968a54658e5a770fd698 88ac 
# c800000000000000
# 19
# 76a9 14 718d1845aeac0ea41e170ab67b1752176c712e8e 88ac
# 00000000


# 49
# 30
# 46
# 02
# 21
# 0090c4fc2369cf225559c1141a1e9be3d7598f0fb7affe8a29f86e737972c7587a
# 02
# 21
# 00cbd8619ecae3baa40fdb565014fdac28a95deb90c0fcd4adcbd97d58d0e96f98
# 01
# 410442718de90a0a10f0cd10054ff4ab6037fd230c5d4b50c07eed0bc247e1e3dbd9ad3f4c65680396813bd96b0c2db5647e355082db34c7106a74337d51e5730f45


# 01000000
# 01
# 4a4b704ff2ce413f25cbdcff9fe018f886e3bc27f5ca01ed3acd736273307406
# 01000000
# 6a
#     48
#     30
#     44
#     02
#     20
#     7b a2 86 6f 5b 20 b9 1a cb 07 11 bd a2 53 52 e5 38 df ec e3 ae 88 40 83 55 98 f2 82 fa 1c 07 9d
#     02
#     20
#     4f 48 e2 f1 8a 99 bb eb cc 2c 13 7c 24 60 04 bb 8d 4b e3 3f c8 79 19 b4 9f 95 77 ba ca c3 d6 da
#     01
#     21
#     03 99 66 42 f7 a5 37 3f 41 d9 81 0c e1 8e 67 e8 5d 07 10 72 b0 4b 39 d2 30 30 0e 62 a3 e7 4e 1c c5
# ffffffff
# 02
# e803000000000000
# 1976a914b0e954f0ea07278c7497968a54658e5a770fd69888ac
# c800000000000000
# 1976a914718d1845aeac0ea41e170ab67b1752176c712e8e88ac
# 00000000
# 01000000