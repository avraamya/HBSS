#! /usr/bin/env python3

import os
import sys
from subprocess import DEVNULL, run
from file_utils import config, generate_file_names, get_current_date


def main():

    files_names = generate_file_names(config)
    print(files_names)
    current_date = get_current_date()

    if not os.path.exists("output"):
        os.mkdir("output")

    for file_name in files_names:
        output_file_name = os.path.join("output", f'{file_name}_output_{current_date}.txt')    
        with open(output_file_name, 'w') as output_file:
            for i in range(config['number_of_runs']):
                print("Benchmarking hbss_{} - Run {}".format(file_name, i+1), flush=True)
                params = 'FILE_NAME={}'.format(file_name)
                run(["make", "clean"], stdout=DEVNULL, stderr=sys.stderr)
                run(["make", params], stdout=DEVNULL, stderr=sys.stderr)
                run(["./benchmark"], stdout=output_file, stderr=sys.stderr)
                output_file.write('\n')
                print(flush=True)

if __name__ == "__main__":
    main()   