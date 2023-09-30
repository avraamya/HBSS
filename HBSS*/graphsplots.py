import numpy as np
import matplotlib.pyplot as plt
from file_utils import get_current_date
from matplotlib.ticker import FuncFormatter
import math

def format_sci_notation_with_value(val, pos):
    if val == 0:
        return '0'
    
    exponent = math.floor(math.log10(abs(val)))
    mantissa = val / (10 ** exponent)

    return r'${0:.1f} \times 10^{{ {1} }}$'.format(mantissa, exponent)


def main():

    current_date = get_current_date() 
    file_name = f'results_output_{current_date}.txt'

    data = np.loadtxt('output/' + file_name, skiprows=2)


    n_signatures = data[:, 3]
    key_cycles = data[:, 8]
    sign_cycles = data[:, 9]
    verify_cycles = data[:, 10]
    steps = data[:, 11]

    unique_steps = np.unique(steps)


    plt.figure(figsize=(10, 6))
    for step in unique_steps:
        mask = steps == step
        filtered_n_signatures = n_signatures[mask]
        filtered_key_cycles = key_cycles[mask]
        plt.plot(filtered_n_signatures, filtered_key_cycles, marker='o',label=f'Step {step}')
    plt.xlabel('Signatures')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_sci_notation_with_value))
    plt.ylabel('Cycles')
    plt.title('Cycles vs. Number of signatures')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f'output/key_cycles_all_steps_' + current_date + '.png')
    plt.close()


    plt.figure(figsize=(10, 6))
    for step in unique_steps:
        mask = steps == step
        filtered_n_signatures = n_signatures[mask]
        filtered_sign_cycles = sign_cycles[mask]
        plt.plot(filtered_n_signatures, filtered_sign_cycles, marker='o', label=f'Step {step}')
    plt.xlabel('Signatures')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_sci_notation_with_value))
    plt.ylabel('Cycles')
    plt.title('Cycles vs. Number of signatures')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f'output/sign_cycles_all_steps_' + current_date + '.png')
    plt.close()

    plt.figure(figsize=(10, 6))
    for step in unique_steps:
        mask = steps == step
        filtered_n_signatures = n_signatures[mask]
        filtered_verify_cycles = verify_cycles[mask]
        plt.plot(filtered_n_signatures, filtered_verify_cycles, marker='o', label=f'Step {step}')
    plt.xlabel('Signatures')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_sci_notation_with_value))
    plt.ylabel('Cycles')
    plt.title('Cycles vs. Number of signatures')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f'output/verify_cycles_all_steps_' + current_date + '.png')
    plt.close()

if __name__ == "__main__":
    main()