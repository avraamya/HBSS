import os
import re
from statistics import median, mean
import datetime
import math

#parameters for stateless lamport
config = {
    "key_sizes" : [256],
    "digest_len_ks" : [512],
    "ms" : [2048], #ms is power of 2
    "random_message_sizes" : [0],
    "number_of_runs" : 5
}    
#functions for stateless lamport
def create_header_file(key_size, digest_len_k, m, random_message_size):
    key_size_bytes = key_size // 8
    digest_len_k_bytes = digest_len_k // 8
    n_signatures_total = (int)(m * 0.6931471805599453) // digest_len_k
    len_m = (int) (math.log(m, 2))

    filename = generate_file_name(key_size, digest_len_k, m, random_message_size)

    parameter_name = f"params-hbss-{filename}.h"
    content = f"""#ifndef {parameter_name[:-2].upper()}    

#define {parameter_name[:-2].upper()}

#define KEY_SIZE {key_size}
#define KEY_SIZE_BYTES {key_size_bytes}
#define DIGEST_LEN_K {digest_len_k}
#define DIGEST_LEN_K_BYTES {digest_len_k_bytes}
#define M {m}
#define LEN_M {len_m}
#define N_SIGNATURES_TOTAL {n_signatures_total}
#define RANDOM_MESSAGE_SIZE {random_message_size}

#endif
"""

    with open(os.path.join("params", parameter_name), "w") as f:
        f.write(content)

def iterate_params(config, callback):
    for key_size in config["key_sizes"]:
        for digest_len_k in config["digest_len_ks"]:
            for m in config["ms"]:
                for random_message_size in config["random_message_sizes"]:
                    callback(key_size, digest_len_k, m, random_message_size)

def generate_file_name(key_size, digest_len_k, m, random_message_size):
    params = {
        "m": m,
        "ks": key_size,
        "k": digest_len_k,
        "msg": random_message_size
    }
    return ''.join(f"{k.upper()}{v}" for k, v in params.items())


def generate_file_names(config):
    file_names = []

    def append_file_name(key_size, digest_len_k, m, random_message_size):
        file_name = generate_file_name(key_size, digest_len_k, m, random_message_size)
        file_names.append(file_name)
    
    iterate_params(config, append_file_name)
    return file_names

def process_output_file(output_file_name):

    output_file_path = os.path.join("output", output_file_name)
    with open(output_file_path, 'r') as output_file:
        content = output_file.read()

    parameters_pattern = r'Parameters: M = (\d+), KEY_SIZE = (\d+), .*DIGEST_LEN_K = (\d+). .*N_SIGNATURES_TOTAL = (\d+) .*RANDOM_MESSAGE_SIZE = (\d+)'

    m, key_size, digest_len, n_signatures_total, message_size = map(int, re.search(parameters_pattern, content).groups())

    generate_key_pair_pattern_avg = r'Generate key pair\.\.\. .*?(\d+\.\d+) us'
    sign_message_pattern_avg = r'Sign message\.\.\. .*?(\d+\.\d+) us'
    verify_signature_pattern_avg = r'Verify signature\.\.\. .*?(\d+\.\d+) us'

    generate_key_pair_timings = [float(x) for x in re.findall(generate_key_pair_pattern_avg, content)]
    sign_message_timings = [float(x) for x in re.findall(sign_message_pattern_avg, content)]
    verify_signature_timings = [float(x) for x in re.findall(verify_signature_pattern_avg, content)]

    key_pair_avg = mean(generate_key_pair_timings)
    sign_avg = mean(sign_message_timings)
    verify_avg = mean(verify_signature_timings)

    generate_key_pair_pattern_median = r'Generate key pair\.\.\. .*?(\d+) cycles'
    sign_message_pattern_median = r'Sign message\.\.\. .*?(\d+) cycles'
    verify_signature_pattern_median = r'Verify signature\.\.\. .*?(\d+) cycles'

    generate_key_pair_cycles = [int(x) for x in re.findall(generate_key_pair_pattern_median, content)]
    sign_message_cycles = [int(x) for x in re.findall(sign_message_pattern_median, content)]
    verify_signature_cycles = [int(x) for x in re.findall(verify_signature_pattern_median, content)]

    key_pair_median = median(generate_key_pair_cycles)
    sign_median = median(sign_message_cycles)
    verify_median = median(verify_signature_cycles)

    print("m = {}, key_size = {}, digest_len = {}, n_signatures_total = {}, message_size = {}".format(m, key_size, digest_len, n_signatures_total, message_size))    
    print("key pair avg = {} us, sign avg = {} us, verify avg = {} us".format(key_pair_avg, sign_avg, verify_avg))
    print("key pair median = {} cycles, sign median = {} cycles, verify median = {} cycles".format(key_pair_median, sign_median, verify_median))
    return m, key_size, digest_len, n_signatures_total, message_size, key_pair_avg, sign_avg, verify_avg, key_pair_median, sign_median, verify_median

def get_current_date():
    return datetime.date.today().strftime('%Y%m%d')

def get_format():

    headers = ["M", "KEY_SIZE", "DIGEST_LEN", "N_SIGNATURES_TOTAL", "RANDOM_MESSAGE_SIZE",
                     "key Avg (us)", "Sign Avg (us)", "Verify Avg (us)", "key cycles", "Sign cycles", "Verify cycles"]
    header_format = '{:^20}' *  5 + '{:^20}' * 6 + '\n'
    row_format = '{:^20}' *  5 + '{:^20.2f}' * 3 + '{:^20}' * 3 + '\n'

    separator = '-' * 20 * len(headers) + '\n'

    return headers, header_format, row_format, separator

