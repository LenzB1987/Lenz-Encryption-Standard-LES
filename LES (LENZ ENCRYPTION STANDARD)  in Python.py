import binascii
import os
import struct
from typing import Union, Tuple, Optional
import mimetypes

class LES:
    """
    Enhanced Lenz Encryption Standard (LES) implementation
    Supports text, binary files, images, and includes proper error handling
    """
    
    def __init__(self, key: int):
        """
        Initialize LES with an encryption key
        
        Args:
            key (int): The encryption/decryption key (n in the LES formula)
        """
        if not isinstance(key, int):
            raise ValueError("Key must be an integer")
        if key == 0:
            raise ValueError("Key cannot be zero")
        self.key = key
        self.chunk_size = 8192  # For handling large files
    
    def _validate_file_path(self, path: str, check_exists: bool = True) -> None:
        """Validate file path and permissions"""
        if not isinstance(path, str):
            raise ValueError("File path must be a string")
        if not path.strip():
            raise ValueError("File path cannot be empty")
        if check_exists and not os.path.exists(path):
            raise FileNotFoundError(f"No such file or directory: '{path}'")
        if check_exists and not os.access(path, os.R_OK):
            raise PermissionError(f"Read permission denied: '{path}'")
    
    def _text_to_hex(self, text: str) -> str:
        """Convert text to hexadecimal representation"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        return binascii.hexlify(text.encode('utf-8')).decode('utf-8')
    
    def _hex_to_text(self, hex_str: str) -> str:
        """Convert hexadecimal back to text"""
        try:
            return binascii.unhexlify(hex_str.encode('utf-8')).decode('utf-8')
        except binascii.Error as e:
            raise ValueError("Invalid hexadecimal string") from e
    
    def _binary_to_hex(self, binary_data: bytes) -> str:
        """Convert binary data to hexadecimal"""
        return binascii.hexlify(binary_data).decode('utf-8')
    
    def _hex_to_binary(self, hex_str: str) -> bytes:
        """Convert hexadecimal back to binary"""
        try:
            return binascii.unhexlify(hex_str.encode('utf-8'))
        except binascii.Error as e:
            raise ValueError("Invalid hexadecimal string") from e
    
    def _apply_les(self, hex_str: str, encrypt: bool = True) -> str:
        """
        Apply LES algorithm to hexadecimal string
        
        Args:
            hex_str: Input hexadecimal string
            encrypt: True for encryption, False for decryption
            
        Returns:
            Processed hexadecimal string
        """
        if not all(c in '0123456789abcdef' for c in hex_str.lower()):
            raise ValueError("Input must be a valid hexadecimal string")
        
        result = []
        power = self.key if encrypt else -self.key
        
        for char in hex_str.lower():
            num = int(char, 16)
            processed_num = (num + power) % 16
            result.append(f"{processed_num:x}")
        
        return ''.join(result)
    
    def encrypt_text(self, plaintext: str) -> str:
        """
        Encrypt text using LES algorithm
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted hexadecimal string
            
        Raises:
            ValueError: If input is not valid text
        """
        try:
            hex_str = self._text_to_hex(plaintext)
            return self._apply_les(hex_str, encrypt=True)
        except Exception as e:
            raise ValueError(f"Text encryption failed: {str(e)}") from e
    
    def decrypt_text(self, ciphertext: str) -> str:
        """
        Decrypt text using LES algorithm
        
        Args:
            ciphertext: Encrypted hexadecimal string
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If decryption fails
        """
        try:
            processed_hex = self._apply_les(ciphertext, encrypt=False)
            return self._hex_to_text(processed_hex)
        except Exception as e:
            raise ValueError(f"Text decryption failed: {str(e)}") from e
    
    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Encrypt any file using LES algorithm
        
        Args:
            input_path: Path to input file
            output_path: Path to save encrypted file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            PermissionError: If file access is denied
            ValueError: If encryption fails
        """
        try:
            self._validate_file_path(input_path)
            self._validate_file_path(output_path, check_exists=False)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            
            with open(input_path, 'rb') as fin, open(output_path, 'w') as fout:
                while True:
                    chunk = fin.read(self.chunk_size)
                    if not chunk:
                        break
                    hex_str = self._binary_to_hex(chunk)
                    encrypted_hex = self._apply_les(hex_str, encrypt=True)
                    fout.write(encrypted_hex)
        except Exception as e:
            raise ValueError(f"File encryption failed: {str(e)}") from e
    
    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Decrypt a file encrypted with LES algorithm
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            PermissionError: If file access is denied
            ValueError: If decryption fails
        """
        try:
            self._validate_file_path(input_path)
            self._validate_file_path(output_path, check_exists=False)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            
            with open(input_path, 'r') as fin, open(output_path, 'wb') as fout:
                while True:
                    chunk = fin.read(self.chunk_size * 2)  # Hex is 2x binary size
                    if not chunk:
                        break
                    processed_hex = self._apply_les(chunk, encrypt=False)
                    binary_data = self._hex_to_binary(processed_hex)
                    fout.write(binary_data)
        except Exception as e:
            raise ValueError(f"File decryption failed: {str(e)}") from e
    
    def encrypt_image(self, image_path: str, output_path: str) -> None:
        """
        Encrypt an image file using LES algorithm
        
        Args:
            image_path: Path to input image
            output_path: Path to save encrypted image
            
        Raises:
            ValueError: If file is not a valid image
        """
        if not self.is_image_file(image_path):
            raise ValueError("File is not a recognized image format")
        self.encrypt_file(image_path, output_path)
    
    def decrypt_image(self, encrypted_path: str, output_path: str) -> None:
        """
        Decrypt an image encrypted with LES algorithm
        
        Args:
            encrypted_path: Path to encrypted image
            output_path: Path to save decrypted image
        """
        self.decrypt_file(encrypted_path, output_path)
    
    def is_image_file(self, file_path: str) -> bool:
        """
        Check if a file is an image based on its MIME type
        
        Args:
            file_path: Path to the file
            
        Returns:
            bool: True if file is an image, False otherwise
        """
        self._validate_file_path(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type is not None and mime_type.startswith('image/')
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect the type of file (text, image, binary)
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: File type ('text', 'image', 'binary')
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        self._validate_file_path(file_path)
        
        if self.is_image_file(file_path):
            return 'image'
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read(1024)  # Try reading as text
            return 'text'
        except UnicodeDecodeError:
            return 'binary'

# Example usage with proper error handling
if __name__ == "__main__":
    try:
        # Initialize with a key
        les = LES(key=5)
        
        # Create example file if it doesn't exist
        if not os.path.exists("example.txt"):
            with open("example.txt", "w") as f:
                f.write("This is a test file for LES encryption.")
            print("Created example.txt for testing")
        
        # Text encryption/decryption example
        text = "Hello, this is a secret message!"
        print(f"\nText Encryption Test:")
        print(f"Original text: {text}")
        
        encrypted_text = les.encrypt_text(text)
        print(f"Encrypted text: {encrypted_text}")
        
        decrypted_text = les.decrypt_text(encrypted_text)
        print(f"Decrypted text: {decrypted_text}")
        
        # File encryption/decryption example
        input_file = "example.txt"
        encrypted_file = "example.les"
        decrypted_file = "example_decrypted.txt"
        
        print(f"\nFile Encryption Test:")
        print(f"Encrypting {input_file} to {encrypted_file}")
        
        # Encrypt
        les.encrypt_file(input_file, encrypted_file)
        print(f"File encrypted successfully")
        
        # Verify encrypted file exists
        if os.path.exists(encrypted_file):
            print(f"Encrypted file size: {os.path.getsize(encrypted_file)} bytes")
        
        # Decrypt
        print(f"\nDecrypting {encrypted_file} to {decrypted_file}")
        les.decrypt_file(encrypted_file, decrypted_file)
        print(f"File decrypted successfully")
        
        # Compare original and decrypted
        with open(input_file, "r") as orig, open(decrypted_file, "r") as dec:
            original_content = orig.read()
            decrypted_content = dec.read()
            if original_content == decrypted_content:
                print("Decrypted file matches original!")
            else:
                print("Warning: Decrypted content doesn't match original!")
    
    except Exception as e:
        print(f"\nError occurred: {str(e)}")