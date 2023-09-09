import os
from file_utils import config, generate_file_names, get_current_date, process_output_file, get_format

def main ():
    current_date = get_current_date()

    files_names = generate_file_names(config)

    output_file_name = os.path.join("output", f'results_output_{current_date}.txt')
    with open(output_file_name, 'w') as output_file:

        headers, header_format, row_format, separator = get_format()

        output_file.write(header_format.format(*headers))
        output_file.write(separator)

        for file_name in files_names:
            input_file_name = f'{file_name}_output_{current_date}.txt'
            print (input_file_name)

            m, key_size, digest_len, n_signatures_total, message_size, gen_key_pair_avg, sign_msg_avg, verify_sig_avg, gen_key_pair_median, sign_msg_median, verify_sig_median = process_output_file(input_file_name)

            row = [m, key_size, digest_len, n_signatures_total, message_size,
                   gen_key_pair_avg, sign_msg_avg, verify_sig_avg,
                   gen_key_pair_median, sign_msg_median, verify_sig_median]
            output_file.write(row_format.format(*row))

        #output_file.write(separator)

if __name__ == "__main__":
    main()