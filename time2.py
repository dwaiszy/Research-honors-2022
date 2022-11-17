import timeit


import_mod = """import math
import time
import timeit
from random import Random, random
import sys
import numpy as np
from reedsolo import RSCodec
from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine

sys.path.insert(1, '/Users/luuyn/research_py/kzg_data_availability/')
sys.path.insert(2, '/Users/luuyn/research_py/TSS/')

import kzg_data_availability.kzg_proofs as PC
from VectorCommitment import VectorCommitment as VC
from TSS import threshold_signature as TSS
from TSS.sign_message import message_digest"""

testingcode = """
def encode(n, k,  m):
    coder = RSCodec(n-k)
    m_n = coder.encode(m)
    return list(m_n)


def decode(n, k, m_n):
    coder = RSCodec(n-k)
    m, m_n, err = coder.decode(bytes(m_n), erase_pos=[0])
    # maxerrors, maxerasures = coder.maxerrata(verbose=True)
    # print(maxerrors, maxerasures)
    return list(m)

# Veriry 2 VCs
def verifyCom(com1, com2):
    if com1 == com2:
        return True
    else:
        return False

def dispersal_data_and_commitment_merkle(n, k, data):
    global tree

    proof_list1 = []
    proof_list2 = []
    
    encoded_data = encode(n, k, data) 
    tree = MerkleTree()

    '''this create tree, not proof'''
    for i in range(len(encoded_data)):
        tree.encrypt(str(encoded_data[i]))
        
    root = tree.get_root_hash()
    for i in range(len(encoded_data)):
        str_data = str(encoded_data[i])

        challenge = HashEngine(**tree.get_config()).hash(str_data.encode())
        proof1 = tree.generate_audit_proof(challenge)
        proof_list1.append(proof1)

        root = tree.get_root_hash()
        
        proof2 = tree.generate_consistency_proof(challenge=root)
        proof_list2.append(proof2)


    return root, proof_list1, proof_list2, encoded_data


def dispersal_ver_proof_merkle(proof_list1, proof_list2, n)-> bool:
    for i in range(n):
        if (proof_list1[i].verify() == True) and ( proof_list2[i].verify() == True):
            return True
        else: 
            return False





#Distribute shared secret. note that share=SK (k_i.G) and pubkey = PK (x, y)
def dispersal_tss_receiver_shares(n, threshold):
    #Suppose key distributor does this
    global ts 
    k =int(((n - 1)/2)+1)
    ts = TSS.ThresholdSignature(n, k)
    shares, pk = ts.jvrss()
    k_i = ts.invss(shares)
    # print("public key - return at jvrss: ", pk)
    return k_i, pk


#Partial sign for P_i
def disperal_tss_receiver_partial_sign(k_i, pubkey, msg):
    #generate share signature s_i
    r, s_i, recovery_id, pk = ts.sign_partial(k_i, pubkey, msg)

    return r, s_i, recovery_id, pk


def dispersal_receiver_send_ok_msg(com, r, s_i, P_s):
    ok_msg = 'OK'
    return com, r, s_i, P_s, ok_msg


#interpole partial signature and verify using EADSA standard for sender
def dispersal_tss_sender_sign_verify(r, s_i, pubkey, recovery_id, msg): 
    
    pk, serialized_sig, s = ts.interpole_and_prep_ver(r, s_i, recovery_id, pubkey)


    ver = TSS.verify_message(pk, msg, serialized_sig)
    return ver, s




def recast_client_ok_msg(com1, r, s, P_s):
    ok_msg = 'OK'
    return com1, r, s, P_s, ok_msg

def recast_receiver_verify_send_merkle(root, root1, recovery_id, r, s, P_s)-> bool:
    #Ver ok-msg
    publickey, sig = ts.sign_message(recovery_id, r, s)
    ver_sign = TSS.verify_message(publickey, root1, sig)
    if not (ver_sign == True):
        ver_com = verifyCom(root1, root)
        if not (ver_com == True) and (P_s == P_s): 
            return False
        else: 
            return True
    else: 
        return True

def recast_return_data_merkle(ver, encoded_data,root, proof_list1, proof_list2):
    if ver ==True:
        return encoded_data, root, proof_list1, proof_list2

def recast_verify_merkle(encoded_data, proof_list1, proof_list2, n, k):
    for i in range(len(encoded_data)):
        if (proof_list1[i].verify()==True) and ( proof_list2[i].verify() == True):
            error_data = encoded_data
            data  = decode(n, k, error_data)
            return data 
        else:
            return False
       
def recast_encode_root(data, n, k):
    
    tree = MerkleTree()
    encode_data = encode(n, k, data) 
    
    for data in str(encode_data):
        tree.encrypt(data)

    root = tree.get_root_hash()
    
    return root

def main():

    n = 16
    k = 4
    
    data = [224, 80, 50, 9]
    P_s = 1
    root, proof_list1, proof_list2, encoded_data_mt = dispersal_data_and_commitment_merkle(n, k, data)
    
    if (dispersal_ver_proof_merkle(proof_list1, proof_list2, n) == True):
        k_i_vt,  pk_vt = dispersal_tss_receiver_shares(n, k)
    else: print("cannot verify")
    
    r_vt, s_i_vt, recovery_id_vt, pk_vt = disperal_tss_receiver_partial_sign(k_i_vt, pk_vt, str(root))
    root, r_vt, s_i_vt, P_s, ok = dispersal_receiver_send_ok_msg(root, r_vt, s_i_vt, P_s)
    
    ver_vt, s_vt = dispersal_tss_sender_sign_verify(r_vt, s_i_vt, pk_vt, recovery_id_vt, str(root))
    
   
    #Recast

    
    root1 = root
    root1, r_vt, s_vt, P_s, ok_msg = recast_client_ok_msg(str(root1), r_vt, s_vt, P_s)

    ver_mt = recast_receiver_verify_send_merkle(str(root), str(root1), recovery_id_vt, r_vt, s_vt, P_s)
  
    if ver_mt == True:
    
    
        encoded_data_mt1, root1_p, proof_list1p, proof_list2p = recast_return_data_merkle(ver_mt, encoded_data_mt, root, proof_list1, proof_list2)
    else:
        print("cannot ver_mt")
    decode_data_mt =  recast_verify_merkle(encoded_data_mt1,proof_list1p, proof_list2p, n, k)

    root_final = recast_encode_root(decode_data_mt, n, k)
    
    ver_root = verifyCom(root1_p, root_final)

main()"""


print(timeit.timeit(stmt=testingcode, setup=import_mod, number=10)/10)