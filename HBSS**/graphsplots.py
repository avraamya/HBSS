import numpy as np
import matplotlib.pyplot as plt
from file_utils import get_current_date

def main():

    # Load data from the file into a numpy array
    current_date = get_current_date()
    file_name = f'results_output_{current_date}.txt'

    data = np.loadtxt('output/' + file_name, skiprows=2)

    # Extract the desired columns
    n_signatures = data[:, 3]
    key_cycles = data[:, 8]
    sign_cycles = data[:, 9]
    verify_cycles = data[:, 10]

    # Plot the data
    # Plot for Key Cycles
    plt.figure(figsize=(10, 6))
    plt.plot(n_signatures, key_cycles, marker='o', color='blue', label='Key Cycles')
    plt.xlabel('N_SIGNATURES_TOTAL')
    plt.ylabel('Key Cycles')
    plt.title('Key Cycles vs. N_SIGNATURES_TOTAL')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('output/key_cycles' + current_date + '.png')
    
    # Plot for Sign Cycles
    plt.figure(figsize=(10, 6))
    plt.plot(n_signatures, sign_cycles, marker='o', color='green', label='Sign Cycles')
    plt.xlabel('N_SIGNATURES_TOTAL')
    plt.ylabel('Sign Cycles')
    plt.title('Sign Cycles vs. N_SIGNATURES_TOTAL')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('output/sign_cycles' + current_date + '.png')

    # Plot for Verify Cycles
    plt.figure(figsize=(10, 6))
    plt.plot(n_signatures, verify_cycles, marker='o', color='red', label='Verify Cycles')
    plt.xlabel('N_SIGNATURES_TOTAL')
    plt.ylabel('Verify Cycles')
    plt.title('Verify Cycles vs. N_SIGNATURES_TOTAL')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('output/verify_cycles' + current_date + '.png')

if __name__ == "__main__":
    main()