import matplotlib.pyplot as plt
import numpy as np
# Define data values
nodes = ['(4, 2)', '(8, 2)', '(8, 3)', '(16, 3)', '(16, 4)', '(32, 4)', '(16, 5)', '(32, 5)', '(16, 6)', '(32, 6)', '(32, 7)', '(64, 22)']
merkle = [0.1,0.14,0.27,0.3,0.16,0.16,0.25,0.22,0.15,0.18,0.36,1.83]
poly = [0.22, 0.34, 0.82, 0.6,0.54,1.68,1.16,1.2,1.09,1.14,0.87,2.77]
vector = [0.3,0.66,0.42,0.25,0.2,0.75,0.34,0.91,0.7,0.23,0.29, 3.0]

# Plot a simple line chart
plt.plot(nodes, merkle, 'r', label='Merkle Tree-VC')

plt.plot(nodes, poly, 'g', label='Polynomial Commitment')
plt.plot(nodes, vector, 'b', label=' RSA-VC')
plt.title("Recast: n < 3f +1, k = f + 1")
plt.legend()
plt.show()