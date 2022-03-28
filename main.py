import struct
import base58

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

prv_txid = "f4cb4fd8680a664544105ac6e2db0a0a54b8c6cd3f9ba184c5649d63a98731f2"

user1_wallet_address = "mxXXcgUWymuGWJ3ekk9q3eLr639e7SRNfN"
user1_hashed_pub_key = base58.b58decode_check(user1_wallet_address)[1:]
user1_pvt_key = "cT2gHVP6z7wtsGSArVBmmWq4MFEhSMr7ZdhKU7fHh8VRFPHJPE5d"
user1_pub_key = "023cbd69b82698d2c3bb339c75a86cfbafcd20a60fad40e3a526603ec1b39afc96"

user2_wallet_address = "mtXh676GL8mQFWTz2n1Gpcrv4DKm2VMneH"
user2_hashed_pub_key = base58.b58decode_check(user2_wallet_address)[1:]
user2_pvt_key = "cVzgiqFDjkHmqMTd1Cv3bxNTyEGhgmKG7Dhpb6EzVuM7UmhYWFaJ"
user2_pub_key = "037ec11fecacf6ee4377193e5af93e6e471f6adeabd6c89d5cc45d51aa4994e5dd"


class main_wrapper():
    version         = struct.pack("<L", 1)
    tx_in_count     = struct.pack("<B",1)
    tx_in           = {}
    tx_out_count    = struct.pack("<B",2)
    tx_out1         = {}
    tx_out2         = {}
    lock_time       = struct.pack("<L",0)

def reverse_byte_order(string):
    reversed_order = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)])).encode()
    return reversed_order

rtx = main_wrapper()

rtx.tx_in["txouthash"]      = reverse_byte_order(prv_txid)
rtx.tx_in["tx_in_index"]    = struct.pack("<L",1)
rtx.tx_in["script"]         = "76a914".encode() + user1_hashed_pub_key + "88ac".encode() #("76a914%s88ac", user1_hashed_pub_key)
rtx.tx_in["script_bytes"]   = struct.pack("<B", len(rtx.tx_in["script"]))
rtx.tx_in["sequence"]       = "ffffffff".encode()

rtx.tx_out1["value"]            = struct.pack("<Q", 100000) #change the value
rtx.tx_out1["pk_script"]        = "76a914".encode() + user2_hashed_pub_key + "88ac".encode()
rtx.tx_out1["pk_script_bytes"]  = struct.pack("<B", len(rtx.tx_out1["pk_script"]))

rtx.tx_out2["value"]            = struct.pack("<Q", 100000) #change the value
rtx.tx_out2["pk_script"]        = "76a914".encode() + user1_hashed_pub_key + "88ac".encode()
rtx.tx_out2["pk_script_bytes"]  = struct.pack("<B", len(rtx.tx_out2["pk_script"]))

raw_tx_string = (

    rtx.version
    + rtx.tx_in_count
    + rtx.tx_in["txouthash"]
    + rtx.tx_in["tx_in_index"]
    + rtx.tx_in["script_bytes"]
    + rtx.tx_in["script"]
    + rtx.tx_in["sequence"]
    + rtx.tx_out_count
    + rtx.tx_out1["value"]
    + rtx.tx_out1["pk_script_bytes"]
    + rtx.tx_out1["pk_script"]
    + rtx.tx_out2["value"]
    + rtx.tx_out2["pk_script_bytes"]
    + rtx.tx_out2["pk_script"]
    + rtx.lock_time
    + struct.pack("<L",1)
)

print(raw_tx_string)


# OP_DUP 76
# OP_HASH160 a9
# ba95f413f2ffbb6a06fb023329e6d09063dce7d9
# OP_EQUALVERIFY 88
# OP_CHECKSIG ac