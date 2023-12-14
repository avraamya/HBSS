# HBSS: Hash-Based Stateless Signatures

## Introduction
This repository, contains the HBSS (Hash-Based Stateless Signatures) implementation from our paper. HBSS offers a novel, efficient approach to cryptographic structures, ensuring post-quantum security.

## Prerequisites
- Knowledge in cryptographic algorithms and hash functions.
- Proficient in Python and C.
- Operating System: Ubuntu 20.04.6 LTS.
- Required Libraries: Python (version 3.8+), Matplotlib, libssl-dev.

## Usage
1. **Clone the Project**:
   ```bash
   git clone https://github.com/avraamya/HBSS/
   ```
2. **Navigate to Scheme Folders**:
   - Access the HBSS / HBSS* / HBSS** folders for the desired scheme.
   - To run all schemes, visit each folder separately.
3. **Run Commands**:
   In the terminal, execute:
   ```bash
   python3 generate_param_files.py
   python3 benchmark.py
   python3 benchmarkresults.py
   python3 graphsplots.py
   ```
4. **Output**:
   - The output folders will contain the results, parameter files, and plots.
  
## Features
The HBSS project includes three versions of the hash-based stateless signature algorithm:

1. **HBSS**: The foundational version, showcasing the core concept of hash-based stateless signatures.
2. **HBSS\***: Optimized for memory efficiency, ideal for environments with memory constraints.
3. **HBSS\*\***: Integrates with Merkle trees, offering a balanced approach between memory usage and computational demand, suitable for a variety of cryptographic applications, especially in post-quantum contexts.
