import math
import time
import timeit
from random import Random, random
import sys
import numpy as np
from reedsolo import RSCodec
from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine

import pandas as pd
import numpy as np

sys.path.insert(1, '/Users/luuyn/research_py/kzg_data_availability/')
sys.path.insert(2, '/Users/luuyn/research_py/TSS/')

import kzg_data_availability.kzg_proofs as PC
from VectorCommitment import VectorCommitment as VC
from TSS import threshold_signature as TSS
from TSS.sign_message import message_digest



# RS code encode
# def encode(n, k, l, m):
#     m_n_list =[]
#     coder = RSCodec(n-k)
#     for i in range(l):
#         m_n = coder.encode(m[i])
#         m_n_int = list(m_n)
#         m_n_list.append(m_n_int)
#     return m_n_list
def encode(n, k,  m):
    coder = RSCodec(n-k)
    m_n = coder.encode(m)
    return list(m_n)

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


# Verify VC 
def VC_Ver(com,m_n, i, proof, S, e, n):
    verified = VC.verify(com, m_n[i], i, proof, S, m_n, e, n)
    if(not verified): 
        return False
    else:
        return True

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




##########################################################################
#  DISPERSAL PROTOCOL
##########################################################################

"""VECTOR COMMITMENT (RSA VERSION)"""
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




"""POLYNOMIAL COMMITMENT"""
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



"""MERKLE TREE"""
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

"""THRESHOLD SIGNATURE"""
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
    # print("\n\npk in sign partial: ", pk, "\n\nr: ", r)
    return r, s_i, recovery_id, pk


def dispersal_receiver_send_ok_msg(com, r, s_i, P_s):
    ok_msg = 'OK'
    return com, r, s_i, P_s, ok_msg


#interpole partial signature and verify using EADSA standard for sender
def dispersal_tss_sender_sign_verify(r, s_i, pubkey, recovery_id, msg): 
    
    pk, serialized_sig, s = ts.interpole_and_prep_ver(r, s_i, recovery_id, pubkey)
    # print("\n\npk in interpole: ", pubkey)
    # print("\n\npk base64 encoded: ", pk, "\n\nsig: ", serialized_sig)
    # print("\n\n r:", r, "\n\ncom:", msg)

    ver = TSS.verify_message(pk, msg, serialized_sig)
    return ver, s




##########################################################################
#  RECAST
##########################################################################
"""VECTOR COMMITMENT"""
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



"""POLY COMMIT"""
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

"""MERKLE TREE"""
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

    # print("Enter n, k, l")
    # n = int(input())
    # k = int(input())
    # l = int(input())
    n = 128
    k = 64
    
    
    # data = np.random.randint(0,255,size=(l,n))
    data = [3, 34, 202, 224, 138, 43, 16, 30, 103, 64, 220, 233, 18, 110, 195, 228, 234, 150, 254, 68, 91, 210, 192, 166, 249, 137, 86, 193, 120, 36, 101, 174, 112, 31, 249, 83, 23, 118, 102, 8, 65, 224, 10, 83, 184, 21, 189, 101, 235, 81, 5, 142, 95, 124, 150, 145, 132, 135, 152, 202, 91, 20, 177, 21]
   
    # test_encode = encode(n, k, data)
    # print("\nENCODE DATA:", test_encode)

    P_s = 1

    print("#########################################################################################")
    print("#")
    print("#                                 VECTOR COMMITMENT")
    print("#")
    print("#########################################################################################") 

    
    #---------------------------------Disperal----------------------------------------------

    # code_test_vc = '''
    # start_vc = time.time()
    # dipsersal_vc =time.time()
    # com, encoded_data, proof_list, P_s, S, e, N = dispersal_data_and_commitment(n, k, data)
    # # bool = dispersal_verify_receiver(com, encoded_data, proof_list, P_s, S, e, N)
    # # print("encoded data:", encoded_data)

    # signing_vc = time.time()
    # if (dispersal_verify_receiver(com, encoded_data, proof_list, P_s, S, e, N)) == True: 
    #     k_i,  pk = dispersal_tss_receiver_shares(n, k)
    # else: print("Cannot verify proof and com")

    # r, s_i, recovery_id, pk = disperal_tss_receiver_partial_sign(k_i, pk, str(com))

    # com, r, s_i, P_s, ok = dispersal_receiver_send_ok_msg(com, r, s_i, P_s)
    # ver, s = dispersal_tss_sender_sign_verify(r, s_i, pk, recovery_id, str(com))
    # end_signing_vc = time.time()
    # end_dispersal_vc = time.time()

    
    # # print("Signing time VC:  ", end_signing_vc - signing_vc)
    # print("Dispersal time VC: ", end_dispersal_vc - dipsersal_vc)
        
    # #--------------------------------Recast--------------------------------------------------
    # recast_vc = time.time()
    # com1 = com 
    # com1, r, s, P_s, ok_msg = recast_client_ok_msg(str(com1), r, s, P_s)

    # # a = time.time()
    # ver_vc = recast_receiver_verify_send(str(com), str(com1),recovery_id, r, s, P_s, encoded_data, proof_list)
    # encoded_data1, com1, proof_list1 = return_data(ver_vc, encoded_data, com, proof_list)
    # # print("Verify prrof VC  in %.3f seconds" % ( time.time() - a))
        
    # # a = time.time()
    # decoded_data = recast_verify(encoded_data1, str(com), str(com1), proof_list1, S, e, N, n, k)
    # com1p = recast_encode_com(decoded_data, S, N, n, k)
    # verifyCom(com1p, com1)
    # # print("recast VC  in %.3f seconds" % ( time.time() - a))
        
    # end_recast= time.time()
    # print("Recast time VC:", end_recast-recast_vc)
        
    # end_vc = time.time()
    # print("Time VC:", end_vc - start_vc)

 

    print("#########################################################################################")
    print("#")
    print("#                                 POLYNOMIAL COMMITMENT")
    print("#")
    print("#########################################################################################") 

    #----------------------------------Dispersal----------------------------------------------
    start_pc = time.time()
    
    dispersal_pc = time.time()
    
    encoded_data_poly, poly_com, PC_prooflist, poly, setup = dispersal_data_and_commitment_poly(n, k, data)
    # print("encoded data:", encoded_data_poly)
    signing_PC = time.time()
    
    if (dispersal_verify_receiver_poly(poly_com, encoded_data_poly, PC_prooflist, poly, setup, P_s)) == True: 
        k_i_poly,  pk_poly = dispersal_tss_receiver_shares(n, k)
    else: print("Cannot verify proof and com")

    r_poly, s_i_poly, recovery_id_poly, pk_poly = disperal_tss_receiver_partial_sign(k_i_poly, pk_poly, str(poly_com))
   
    poly_com, r_poly, s_i_poly, P_s, ok = dispersal_receiver_send_ok_msg(poly_com, r_poly, s_i_poly, P_s)
    
    ver_poly, s_poly = dispersal_tss_sender_sign_verify(r_poly, s_i_poly, pk_poly, recovery_id_poly, str(poly_com))
    
    end_dispersal_pc = time.time()
    end_signing_PC = time.time()
    
    # print("Signing PC:", end_signing_PC-signing_PC)
    print("Dispersal time PC: ", end_dispersal_pc  - dispersal_pc)
    
    #--------------------------------------Recast-------------------------------------------
    recast_PC = time.time()
    
    poly_com1 = poly_com
    poly_com1, r_poly, s_poly, P_s, ok_msg = recast_client_ok_msg(str(poly_com1), r_poly, s_poly, P_s)

    ver_pc= recast_receiver_verify_send_poly(str(poly_com), str(poly_com1),recovery_id_poly, r_poly, s_poly, pk_poly, P_s, encoded_data_poly, PC_prooflist)
    
    encoded_data_poly1, poly_com1, PC_prooflist = return_data_poly(ver_pc, encoded_data_poly, poly_com,  PC_prooflist)
    
    decoded_data_poly = recast_verify_poly(encoded_data_poly1, poly_com, poly_com1, PC_prooflist, poly, setup, n, k)
    
    end_recast_PC = time.time()
    print("Recast PC: ", end_recast_PC -recast_PC)
    
    end_pc = time.time()
    print("Time PC:", end_pc - start_pc)


    print("#########################################################################################")
    print("#")
    print("#                                 MERKEL TREE COMMITMENT")
    print("#")
    print("#########################################################################################") 

    start_vt = time.time()
    dispersal_vt=time.time()
    
    root, proof_list1, proof_list2, encoded_data_mt = dispersal_data_and_commitment_merkle(n, k, data)
    
    signing_VT=time.time()
    if (dispersal_ver_proof_merkle(proof_list1, proof_list2, n) == True):
        k_i_vt,  pk_vt = dispersal_tss_receiver_shares(n, k)
    else: print("cannot verify")
    
    r_vt, s_i_vt, recovery_id_vt, pk_vt = disperal_tss_receiver_partial_sign(k_i_vt, pk_vt, str(root))
    root, r_vt, s_i_vt, P_s, ok = dispersal_receiver_send_ok_msg(root, r_vt, s_i_vt, P_s)
    
    ver_vt, s_vt = dispersal_tss_sender_sign_verify(r_vt, s_i_vt, pk_vt, recovery_id_vt, str(root))
    
    end_signing_VT=time.time()
    end_dispersal_vt = time.time()
    
    # print("Signing VT:", end_signing_VT-signing_VT)
    print("Dispersal VT: ", end_dispersal_vt - dispersal_vt)
    
    #Recast
    recast_VT = time.time()
    
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

    
    end_recast_VT = time.time()
    
    end_vt = time.time()
    
    recast_vt_total = end_recast_VT - recast_VT
    time_vt = end_vt-start_vt
    
    print("recast VT: ", recast_vt_total)
    print("Time vt: ", time_vt )


    
    
main()

