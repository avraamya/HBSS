import os
from file_utils import create_header_file,iterate_params, config

def main():

    if not os.path.exists("params"):
        os.mkdir("params")
    
    iterate_params(config, create_header_file)

if __name__ == "__main__":
    main()
