# crypto_core.py
import os
import gzip
import base64
import struct  # 用于将长度打包成 4 字节二进制
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16          
KEY_LENGTH = 32         
ITERATIONS = 100000     

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

# crypto_core.py 中的更新部分

def encrypt_file(input_path: str, password: str, output_txt_path: str, progress_callback=None):
    """支持进度回传的流式加密"""
    if progress_callback:
        progress_callback(0, "🔑 正在初始化并派生密钥...")
        
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # 1. 压缩文件
    if progress_callback:
        progress_callback(10, "📦 正在压缩源文件...")
        
    with open(input_path, 'rb') as f_in:
        plaintext = f_in.read()
        compressed = gzip.compress(plaintext)
    
    total_len = len(compressed)
    CHUNK_SIZE = 512 * 1024 
    cursor = 0
    
    # 2. 分块加密并写入
    if progress_callback:
        progress_callback(20, "🔐 开始分块加密...")

    with open(output_txt_path, 'w') as f_out:
        salt_b32 = base64.b32encode(salt).decode('ascii').lower().replace('=', '')
        f_out.write(salt_b32 + "\n")
        
        while cursor < total_len:
            block = compressed[cursor:cursor+CHUNK_SIZE]
            cursor += CHUNK_SIZE
            
            # 计算当前进度 (从 20% 到 95%)
            percent = int(20 + (cursor / total_len) * 75)
            percent = min(percent, 95) # 保留最后5%给写盘完毕
            
            if progress_callback:
                progress_callback(percent, f"⚡ 正在加密分块: {cursor:,} / {total_len:,} 字节...")

            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, block, None)
            combined = nonce + ciphertext
            
            block_b32 = base64.b32encode(combined).decode('ascii').lower().replace('=', '')
            f_out.write(block_b32 + "\n")
            
    if progress_callback:
        progress_callback(100, "🎉 加密成功，数据流写入完毕！")


def decrypt_file(input_txt_path: str, password: str, output_path: str, progress_callback=None):
    """支持进度回传的流式解密"""
    if progress_callback:
        progress_callback(0, "🔑 正在读取并派生解密密钥...")

    # 获取伪装文件的大小，用以预估解密进度
    total_chars = os.path.getsize(input_txt_path)
    read_chars = 0

    with open(input_txt_path, 'r') as f_in:
        # 读取第一行：盐值
        salt_line = f_in.readline()
        read_chars += len(salt_line)
        salt_line = salt_line.strip()
        if not salt_line:
            raise ValueError("文件损坏，无法读取盐值")
            
        salt_b32_upper = salt_line.upper()
        if len(salt_b32_upper) % 8:
            salt_b32_upper += '=' * (8 - (len(salt_b32_upper) % 8))
        salt = base64.b32decode(salt_b32_upper)
        
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        compressed_data = bytearray()
        
        if progress_callback:
            progress_callback(15, "🔓 开始逐行还原解密数据...")

        # 2. 逐行读取加密块
        for line in f_in:
            read_chars += len(line)
            block_b32 = line.strip()
            if not block_b32:
                continue
                
            percent = int(15 + (read_chars / total_chars) * 70)
            percent = min(percent, 85)
            
            if progress_callback:
                progress_callback(percent, f"⚡ 正在还原并解密数据分块 ({percent}%)...")

            block_b32_upper = block_b32.upper()
            if len(block_b32_upper) % 8:
                block_b32_upper += '=' * (8 - (len(block_b32_upper) % 8))
                
            combined = base64.b32decode(block_b32_upper)
            nonce = combined[:12]
            ciphertext = combined[12:]
            
            decrypted_block = aesgcm.decrypt(nonce, ciphertext, None)
            compressed_data.extend(decrypted_block)
            
        # 3. 解压并写出文件
        if progress_callback:
            progress_callback(90, "📦 正在解压缩还原原始文件...")
            
        plaintext = gzip.decompress(compressed_data)
        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)
            
    if progress_callback:
        progress_callback(100, "🎉 解密成功，原始文件已安全落地！")