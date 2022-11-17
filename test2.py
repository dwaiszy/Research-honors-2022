from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine

tree = MerkleTree()

encoded_data = [30, 151, 237, 111]
# Populate tree with some records

challenge_list = [] 
proof_list1 = []
proof_list2 = []

tree = MerkleTree()

'''this create tree, not proof'''
for i in range(len(encoded_data)):
    tree.encrypt(str(encoded_data[i]))


for i in range(len(encoded_data)):
    
    print(encoded_data[i])
    str_data = str(encoded_data[i])
    print(str_data.encode())
    
    challenge = HashEngine(**tree.get_config()).hash(str_data.encode())
    print(challenge)
    
    
    proof1 = tree.generate_audit_proof(challenge)
    proof1.verify()
    print(proof1)
        
    root = tree.get_root_hash()
    
    proof2 = tree.generate_consistency_proof(challenge=root)
    proof2.verify()

    print(proof2)

        
      
        
        
# from pymerkle import MerkleTree

# tree = MerkleTree()

# # Populate tree with some records
# for data in [b'30', b'151', b'237', b'111']:
#     tree.encrypt(data)

# # Prove and verify encryption of `bar`
# challenge = HashEngine(**tree.get_config()).hash(b'30')
# print(challenge)
# proof1 = tree.generate_audit_proof(challenge)
# print(proof1)
# proof1.verify()

# # Save current tree state
# state = tree.get_root_hash()

# # Append further leaves
# for data in [b'corge', b'grault', b'garlpy']:
#     tree.encrypt(data)

# # Prove and verify saved state
# proof2 = tree.generate_consistency_proof(challenge=state)
# proof2.verify()
# print(proof2)
# print("ROOT", state)


# tree = MerkleTree()

# # Populate tree with some records
# for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
#     tree.encrypt(data)

# # Prove and verify encryption of `bar`
# challenge = b'485904129bdda5d1b5fbc6bc4a82959ecfb9042db44dc08fe87e360b0a3f2501'
# proof = tree.generate_audit_proof(challenge)
# proof.verify()
# print(proof)

# # Save current tree state
# state = tree.get_root_hash()

# # Append further leaves
# for data in [b'corge', b'grault', b'garlpy']:
#     tree.encrypt(data)

# # Prove and verify saved state
# proof1 = tree.generate_consistency_proof(challenge=state)
# proof1.verify()
# print(proof1)