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

def dispersal_data_and_commitment_poly(n, k, data):
    encoded_data = encode(n, k, data) # (m1,...m_n)
    
    poly = PC.get_polynomial(encoded_data)
    poly_len = len(poly) 
    setup = PC_Setup(1927409816240961209460912649124,poly_len)
    poly_com = PC_Com(poly, setup)
    
    PC_prooflist = []
    for i in range(len(encoded_data)):
        PC_proof  = PC_Proof(poly, i, setup)
        PC_prooflist.append(PC_proof)
    
    return encoded_data, poly_com, PC_prooflist, poly, setup

def dispersal_verify_receiver_poly(poly_com, encoded_data, PC_prooflist, poly, setup, P_s):
    for i in range(len(encoded_data)):
        # print(PC_Ver(poly, poly_com, PC_prooflist[i], i, setup))
        if (PC_Ver(poly, poly_com, PC_prooflist[i], i, setup) == True): 
            return True
        else:
            return False

#Polynomial commitment
# PC.Setup(1^k, t - degree)
def PC_Setup(s, n):
    setup = PC.generate_setup(s, n)
    return setup #return commitment key pair Sk, PK - added an algebraic structure G

# PC.Commit(PK, \phi(x) - poly)
def PC_Com(poly, setup):
    com = PC.commit_to_poly(poly, setup)
    return com #return com, poly + d

# PC.Proof computes proof for poly at position i 
def PC_Proof(poly, i, setup):
    proof = PC.compute_proof_single(poly, i, setup)
    return proof


# Verify if value = /phi(i) is the evaluation at i of PC in com. 
def PC_Ver(poly, com, proof, i, setup):
    value = PC.eval_poly_at(poly, i)
    Ver = PC.check_proof_single(com, proof, i, value, setup)
    if(not Ver): 
        print("Fail at proof: ", proof, "and position: ", i)
        return False
    else:
       return True 
   # RS code decode for retrieve 



##########################################################################
#  RECAST
##########################################################################

def recast_client_ok_msg(com1, r, s, P_s):
    ok_msg = 'OK'
    return com1, r, s, P_s, ok_msg
def recast_receiver_verify_send_poly(poly_com, poly_com1, recovery_id, r, s ,pk, P_s, encoded_data, PC_prooflist)-> bool:
    #Ver ok-msg
    publickey, sig = ts.sign_message(recovery_id, r, s)
    ver_sign = TSS.verify_message(publickey, poly_com1, sig)
    if not (ver_sign == True):
        ver_com = verifyCom(poly_com, poly_com1)
        if not (ver_com == True) and (P_s == P_s): 
            return False
        else: 
            return True
    else: 
        return True

def return_data_poly(ver, encoded_data, poly_com, PC_prooflist):
    if ver == True:
        return encoded_data, poly_com, PC_prooflist
    
def recast_verify_poly(encoded_data, poly_com, poly_com1, PC_prooflist, poly, setup, n, k):

    for i in range(len(encoded_data)):
        if (verifyCom(str(poly_com), str(poly_com1)) == True)and (PC_Ver(poly, poly_com, PC_prooflist[i], i, setup) == True):
            error_data = encoded_data
            data  = decode(n, k, error_data)
        return data
    # else: 
    #     return False


def main():


    n = 64
    k = 22

    data =  [224, 80, 50, 9, 89, 145, 97, 3, 65, 2, 161, 195, 191, 134, 192, 229, 13, 201, 192, 206, 89, 74]

    P_s = 1

    encoded_data_poly, poly_com, PC_prooflist, poly, setup = dispersal_data_and_commitment_poly(n, k, data)
    if (dispersal_verify_receiver_poly(poly_com, encoded_data_poly, PC_prooflist, poly, setup, P_s)) == True: 
        k_i_poly,  pk_poly = dispersal_tss_receiver_shares(n, k)
    else: print("Cannot verify proof and com")

    r_poly, s_i_poly, recovery_id_poly, pk_poly = disperal_tss_receiver_partial_sign(k_i_poly, pk_poly, str(poly_com))
   
    poly_com, r_poly, s_i_poly, P_s, ok = dispersal_receiver_send_ok_msg(poly_com, r_poly, s_i_poly, P_s)
    
    ver_poly, s_poly = dispersal_tss_sender_sign_verify(r_poly, s_i_poly, pk_poly, recovery_id_poly, str(poly_com))


    # poly_com1 = poly_com
    # poly_com1, r_poly, s_poly, P_s, ok_msg = recast_client_ok_msg(str(poly_com1), r_poly, s_poly, P_s)

    # ver_pc= recast_receiver_verify_send_poly(str(poly_com), str(poly_com1),recovery_id_poly, r_poly, s_poly, pk_poly, P_s, encoded_data_poly, PC_prooflist)
    
    # encoded_data_poly1, poly_com1, PC_prooflist = return_data_poly(ver_pc, encoded_data_poly, poly_com,  PC_prooflist)
    
    # decoded_data_poly = recast_verify_poly(encoded_data_poly1, poly_com, poly_com1, PC_prooflist, poly, setup, n, k)

main()"""


print(timeit.timeit(stmt=testingcode, setup=import_mod, number=50)/50)