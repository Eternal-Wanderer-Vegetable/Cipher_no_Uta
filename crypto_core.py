# crypto_core.py
import os
import gzip
import base64
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ============ 配置 ============
SALT_SIZE = 16          # 盐值大小（字节）
KEY_LENGTH = 32         # AES-256 密钥长度
ITERATIONS = 100000     # PBKDF2 迭代次数

def derive_key(password: str, salt: bytes) -> bytes:
    """从密码和盐值派生出 AES 密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_path: str, password: str, output_txt_path: str):
    """流式加密文件：流式压缩 → 分块加密 → 流式 Base32 编码输出"""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    
    temp_compressed = tempfile.TemporaryFile()
    
    # 1. 流式 Gzip 压缩
    CHUNK_SIZE = 64 * 1024
    with open(input_path, 'rb') as f_in:
        with gzip.GzipFile(fileobj=temp_compressed, mode='wb') as f_zip:
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                f_zip.write(chunk)
    
    temp_compressed.seek(0)
    
    # 2. 开始分块加密并进行 Base32 写入
    aesgcm = AESGCM(key)
    
    with open(output_txt_path, 'w') as f_out:
        salt_b32 = base64.b32encode(salt).decode('ascii').lower().replace('=', '')
        f_out.write(salt_b32)
        
        ENCRYPT_CHUNK_SIZE = 1024 * 1024 
        while True:
            data_block = temp_compressed.read(ENCRYPT_CHUNK_SIZE)
            if not data_block:
                break
                
            block_nonce = os.urandom(12)
            encrypted_block = aesgcm.encrypt(block_nonce, data_block, None)
            combined_block = block_nonce + encrypted_block
            
            block_b32 = base64.b32encode(combined_block).decode('ascii').lower().replace('=', '')
            f_out.write(block_b32)
            
    temp_compressed.close()

def decrypt_file(input_txt_path: str, password: str, output_path: str):
    """流式解密文件：流式读取文本 → 逐块 Base32 解码 → 逐块 AES-GCM 解密 → 流式解压输出"""
    B32_SALT_LEN = 26
    B32_BLOCK_LEN = 1677768 
    
    with open(input_txt_path, 'r') as f_in:
        salt_b32 = f_in.read(B32_SALT_LEN)
        if not salt_b32:
            raise ValueError("文件损坏，无法读取盐值")
            
        salt_b32_upper = salt_b32.upper() + "=="
        salt = base64.b32decode(salt_b32_upper)
        
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        temp_decrypted = tempfile.TemporaryFile()
        
        while True:
            block_b32 = f_in.read(B32_BLOCK_LEN)
            if not block_b32:
                break
                
            block_b32_upper = block_b32.upper()
            missing_padding = len(block_b32_upper) % 8
            if missing_padding:
                block_b32_upper += '=' * (8 - missing_padding)
                
            combined_block = base64.b32decode(block_b32_upper)
            nonce = combined_block[:12]
            ciphertext = combined_block[12:]
            
            decrypted_block = aesgcm.decrypt(nonce, ciphertext, None)
            temp_decrypted.write(decrypted_block)
            
        temp_decrypted.seek(0)
        
        with gzip.GzipFile(fileobj=temp_decrypted, mode='rb') as f_zip:
            with open(output_path, 'wb') as f_out:
                CHUNK_SIZE = 64 * 1024
                while True:
                    chunk = f_zip.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    
        temp_decrypted.close()