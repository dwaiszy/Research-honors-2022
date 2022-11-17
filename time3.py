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
#Vector commitment
#VC.keyGen(1^k, l, q)
def VC_keyGen(m_n, l):
    n, e, a, S = VC.keygen(m_n, l)
    return n, e, a, S #return public parameter (pp)
    

# VC.Com(m_1...m_n, S, )
def VC_Com(m_n, S, n):
    com = VC.commit(m_n, S, n) #generate commitment com    
    return com


# VC.Open (m, i, aux = (e, a, n))
def VC_Open(m_n, e, a ,n, i):
    proof = VC.open( m_n, e, a, n, i)#create opening (proof) at i -position
    return proof

# Verify VC 
def VC_Ver(com,m_n, i, proof, S, e, n):
    verified = VC.verify(com, m_n[i], i, proof, S, m_n, e, n)
    if(not verified): 
        return False
    else:
        return True



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

def dispersal_data_and_commitment(n, k, data):
    encoded_data = encode(n, k, data) # (m1,...m_n)
    
    N, e, a, S  = VC_keyGen(encoded_data, 8)
    com = VC_Com(encoded_data, S, N) # VC
    
    P_s = 1 #Sent file ID for recast - P_s
    
    proof_list = []    
    for i in range(len(encoded_data)):
        proof = VC_Open(encoded_data, e, a, N, i)
        proof_list.append(proof) #Proof \pi_1...\pi_n
        
    return com, encoded_data, proof_list, P_s, S, e, N

def dispersal_verify_receiver(com, encoded_data, proof_list, P_s, S, e, N):
    for i in range(len(encoded_data)):
        if VC_Ver(com, encoded_data, i, proof_list[i], S, e, N): return True


##########################################################################
#  RECAST
##########################################################################

def recast_client_ok_msg(com1, r, s, P_s):
    ok_msg = 'OK'
    return com1, r, s, P_s, ok_msg
 
def recast_client_ok_msg(com1, r, s, P_s):
    ok_msg = 'OK'
    return com1, r, s, P_s, ok_msg

#Pi verify 
def recast_receiver_verify_send(com, com1, recovery_id, r, s , P_s, encoded_data, proof_list)-> bool:
    #Ver ok-msg
    publickey, sig = ts.sign_message(recovery_id, r, s)
    ver_sign = TSS.verify_message(publickey, com1, sig)
    if not (ver_sign == True):
        if not (verifyCom(com, com1) == True) and (P_s == P_s): 
            return False
        else: 
            return True
    return True

def return_data(ver, encoded_data, com, proof_list):
    if ver == True:
        return encoded_data, com, proof_list
    
        
def recast_verify(encoded_data, com, com1, proof_list, S, e, N, n, k):
    for i in range(len(encoded_data)):
        if (VC_Ver(int(com), encoded_data, i, proof_list[i], S, e, N) == True) and (verifyCom(com1, com)): 
            error_data =encoded_data
            data  = decode(n, k, error_data)
            return data
        else: 
            return False
        
def recast_encode_com(data, S, N, n, k):
    encoded_data = encode(n, k, data)
    com = VC_Com(encoded_data, S, N)
    return com

def main():


    n = 64
    k = 22
    
    data = [224, 80, 50, 9, 89, 145, 97, 3, 65, 2, 161, 195, 191, 134, 192, 229, 13, 201, 192, 206, 89, 74]

    P_s = 1
     #---------------------------------Disperal----------------------------------------------

  
    com, encoded_data, proof_list, P_s, S, e, N = dispersal_data_and_commitment(n, k, data)
    bool = dispersal_verify_receiver(com, encoded_data, proof_list, P_s, S, e, N)
 
  
    if (dispersal_verify_receiver(com, encoded_data, proof_list, P_s, S, e, N)) == True: 
        k_i,  pk = dispersal_tss_receiver_shares(n, k)
    else: print("Cannot verify proof and com")

    r, s_i, recovery_id, pk = disperal_tss_receiver_partial_sign(k_i, pk, str(com))

    com, r, s_i, P_s, ok = dispersal_receiver_send_ok_msg(com, r, s_i, P_s)
    ver, s = dispersal_tss_sender_sign_verify(r, s_i, pk, recovery_id, str(com))
    
    
        
    #--------------------------------Recast--------------------------------------------------
   
    # com1 = com 
    # com1, r, s, P_s, ok_msg = recast_client_ok_msg(str(com1), r, s, P_s)

  
    # ver_vc = recast_receiver_verify_send(str(com), str(com1),recovery_id, r, s, P_s, encoded_data, proof_list)
    # encoded_data1, com1, proof_list1 = return_data(ver_vc, encoded_data, com, proof_list)
  

    # decoded_data = recast_verify(encoded_data1, str(com), str(com1), proof_list1, S, e, N, n, k)
    # com1p = recast_encode_com(decoded_data, S, N, n, k)
    # verifyCom(com1p, com1)


main()"""


print(timeit.timeit(stmt=testingcode, setup=import_mod, number=50)/50)