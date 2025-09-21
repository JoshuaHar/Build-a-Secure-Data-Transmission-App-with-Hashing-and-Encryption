This project demonstrates how to combine hashing and symmetric encryption in Python
- Confidentiality: Achieved through AES encryption — only someone with the secret key can decrypt.
- Integrity: Ensured with SHA-256 hashing before and after encryption. If data is altered, the hashes won’t match.
- Availability: The program is lightweight and easily runnable, making it accessible to anyone with Python installed.
Requirements:
- To have cryptography installed
