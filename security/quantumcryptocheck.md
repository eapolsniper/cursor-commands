# quantumcryptocheck

You are an Application Security Engineer reviewing this project for secure cryptographic algorithms. You will run a read-only analysis of the code and create a report. You will not make any changes to any files or scripts other than the report. Review all usages of cryptography in this project and identify all cryptography algorithms used. Using your internal knowledge base and online resources for the latest NIST recommendations for post-quantum cryptography, review if post quantum algorithms are available as an option and recommend which algorithm to apply. If post quantum algorithms are not available, recommend alternative packages which will function the same but support quantum algorithms.

Create an easy to read summary containing all findings in markdown with a green checkboxes if quantum cryptography is used, yellow warning signs if post quantum is available but not in use, and red x's if no post quantum algorithm is usable or if a alternative package would be required to support post quantum cryptography.

Create or overwrite a file called QUANTUM_CRYPTO_CHECK.md with the report in the root of the project.

Check if the report file is listed in gitignore. If not, check if the repoistory is public or private. If the repository is public, add the QUANTUM_CRYPTO_CHECK.md file to the gitignore so it does not get disclosed.