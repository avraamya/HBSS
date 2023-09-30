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

    plt.figure(figsize=(10, 6))
    plt.plot(n_signatures, key_cycles, marker='o', color='blue')
    plt.xlabel('Signatures')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_sci_notation_with_value))
    plt.ylabel('Cycles')
    plt.title('Cycles vs. Number of signatures')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('output/key_cycles' + current_date + '.png')
    
    plt.figure(figsize=(10, 6))
    plt.plot(n_signatures, sign_cycles, marker='o', color='green')
    plt.xlabel('Signatures')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_sci_notation_with_value))
    plt.ylabel('Cycles')
    plt.title('Cycles vs. Number of signatures')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('output/sign_cycles' + current_date + '.png')

    plt.figure(figsize=(10, 6))
    plt.plot(n_signatures, verify_cycles, marker='o', color='red')
    plt.xlabel('Signatures')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_sci_notation_with_value))
    plt.ylabel('Cycles')
    plt.title('Cycles vs. Number of signatures')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('output/verify_cycles' + current_date + '.png')

if __name__ == "__main__":
    main()