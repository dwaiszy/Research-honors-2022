import matplotlib.pyplot as plt
import numpy as np
# Define data values
nodes = ['(4, 2)', '(8, 2)', '(8, 3)', '(16, 3)', '(16, 4)', '(32, 4)', '(16, 5)', '(32, 5)', '(16, 6)', '(32, 6)', '(32, 7)', '(64, 22)']
merkle = [0.75,1.2,1.1,1.9,2.02,3.87,1.88,3.64,1.91,3.7,3.67,7.04]
poly = [1.7, 2.78,2.01,3.8,4.28,7.72,4.3,8.7,3.72,8.72,10.03,34.11]
vector = [1.66,2,1.95,3.37,3.06,5.9,3.22,5.31,2.9,5.8,5.45, 40]

# Plot a simple line chart
plt.plot(nodes, merkle, 'r', label='Merkle Tree-VC')

# # Plot another line on the same chart/graph
plt.plot(nodes, poly, 'g', label='Polynomial Commitment')
plt.plot(nodes, vector, 'b', label=' RSA-VC')
plt.title("Dispersal:  n < 3f +1, k = f + 1")
plt.legend()
plt.show()