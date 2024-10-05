import sys
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def generate_key(password, key_length = 16, iterations = 1000):
    
    salt = b'\x00'                      # Ένα salt με ένα μόνο byte ίσο με 0

    kdf = PBKDF2HMAC(                   # PBKDF2: Δημιουργία κλειδιών από κωδικούς πρόσβασης
        algorithm = hashes.SHA1(),      # Χρήση του αλγορίθμου κατακερματισμού SHA-1
        length = key_length,            # Μήκος του κλειδιού σε bytes (16 bytes = 128 bits)
        salt = salt,                    # Το salt
        iterations = iterations,        # Ο αριθμός των επαναλήψεων
        backend = default_backend()     # Προεπιλεγμένο backend
    )

    # Δημιουργία κλειδιού από έναν κωδικό πρόσβασης
    key = kdf.derive(password.encode('utf-8'))
    
    return key, salt


# Αποθήκευση κλειδιού και salt σε ένα αρχείο
def save_key_to_file(key, salt, filename):
    key_b64 = base64.b64encode(key)     # Κωδικοποίηση κλειδιού σε base64
    salt_b64 = base64.b64encode(salt)   # Κωδικοποίηση salt σε base64
    
    # Εγγραφή σε αρχείο
    with open(filename, 'wb') as f:
        f.write(key_b64)
        f.write(b'\n')
        f.write(salt_b64)


def main():
    password = input("Εισαγωγή κωδικού πρόσβασης: ")
    filename = input("Εισαγωγή ονόματος αρχείου: ")

    # Δημιουργία κλειδιού και salt
    key, salt = generate_key(password)

    # Αποθήκευση κλειδιού και salt σε αρχείο
    save_key_to_file(key, salt, filename)

    print("Το κλειδί και το salt παράχθηκαν και αποθηκεύτηκαν με επιτυχία!!")


if __name__ == "__main__":
    main()

