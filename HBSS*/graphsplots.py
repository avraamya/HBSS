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
    steps = data[:, 11]

    unique_steps = np.unique(steps)

    for step in unique_steps:
        mask = steps == step
        filtered_n_signatures = n_signatures[mask]
        filtered_key_cycles = key_cycles[mask]
        filtered_sign_cycles = sign_cycles[mask]
        filtered_verify_cycles = verify_cycles[mask]

        # Plot for Key Cycles
        plt.figure(figsize=(10, 6))
        plt.plot(filtered_n_signatures, filtered_key_cycles, marker='o', color='blue', label='Key Cycles')
        plt.xlabel('N_SIGNATURES_TOTAL')
        plt.ylabel('Key Cycles')
        plt.title(f'Key Cycles vs. N_SIGNATURES_TOTAL for Step = {step}')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f'output/key_cycles_{step}_' + current_date + '.png')
        
        # Plot for Sign Cycles
        plt.figure(figsize=(10, 6))
        plt.plot(filtered_n_signatures, filtered_sign_cycles, marker='o', color='green', label='Sign Cycles')
        plt.xlabel('N_SIGNATURES_TOTAL')
        plt.ylabel('Sign Cycles')
        plt.title(f'Sign Cycles vs. N_SIGNATURES_TOTAL for Step = {step}')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f'output/sign_cycles_{step}_' + current_date + '.png')

        # Plot for Verify Cycles
        plt.figure(figsize=(10, 6))
        plt.plot(filtered_n_signatures, filtered_verify_cycles, marker='o', color='red', label='Verify Cycles')
        plt.xlabel('N_SIGNATURES_TOTAL')
        plt.ylabel('Verify Cycles')
        plt.title(f'Verify Cycles vs. N_SIGNATURES_TOTAL for Step = {step}')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f'output/verify_cycles_{step}_' + current_date + '.png')

if __name__ == "__main__":
    main()