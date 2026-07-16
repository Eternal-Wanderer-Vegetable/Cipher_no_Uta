# crypto_core.py
# crypto_core.py
import os
import gzip
import base64
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

def encrypt_file(input_path: str, password: str, output_txt_path: str, progress_callback=None):
    """流式加密：打包[文件名元数据] + [压缩数据]"""
    if progress_callback:
        progress_callback(0, "🔑 正在初始化并派生密钥...")
        
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # 1. 提取并打包源文件名元数据
    # 例如 input_path = "E:/test_file/photo.jpg" -> original_name = "photo.jpg"
    original_name = os.path.basename(input_path)
    name_bytes = original_name.encode('utf-8')
    name_len = len(name_bytes)
    
    if name_len > 255:
        raise ValueError("源文件名过长，最大支持 255 字节！")
        
    # 2. 压缩文件数据
    if progress_callback:
        progress_callback(10, "📦 正在压缩源文件...")
        
    with open(input_path, 'rb') as f_in:
        plaintext = f_in.read()
        compressed = gzip.compress(plaintext)
    
    # 3. 将元数据和压缩数据打包在一起
    # 打包格式：[1字节长度] + [文件名字节] + [压缩数据]
    payload = bytes([name_len]) + name_bytes + compressed
    
    total_len = len(payload)
    CHUNK_SIZE = 512 * 1024 
    cursor = 0
    
    if progress_callback:
        progress_callback(20, "🔐 开始分块加密...")

    # 4. 分块加密写入
    with open(output_txt_path, 'w') as f_out:
        salt_b32 = base64.b32encode(salt).decode('ascii').lower().replace('=', '')
        f_out.write(salt_b32 + "\n")
        
        while cursor < total_len:
            block = payload[cursor:cursor+CHUNK_SIZE]
            cursor += CHUNK_SIZE
            
            percent = int(20 + (cursor / total_len) * 75)
            percent = min(percent, 95)
            
            if progress_callback:
                progress_callback(percent, f"⚡ 正在加密分块: {cursor:,} / {total_len:,} 字节...")

            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, block, None)
            combined = nonce + ciphertext
            
            block_b32 = base64.b32encode(combined).decode('ascii').lower().replace('=', '')
            f_out.write(block_b32 + "\n")
            
    if progress_callback:
        progress_callback(100, "🎉 加密成功，数据流写入完毕！")


def decrypt_file(input_txt_path: str, password: str, output_dir_or_file: str, progress_callback=None):
    """流式解密：解密数据 → 解析出原文件名 → 流式解压输出"""
    if progress_callback:
        progress_callback(0, "🔑 正在读取并派生解密密钥...")

    total_chars = os.path.getsize(input_txt_path)
    read_chars = 0

    with open(input_txt_path, 'r') as f_in:
        # 1. 读取第一行：盐值
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
        
        payload_data = bytearray()
        
        if progress_callback:
            progress_callback(15, "🔓 开始逐行还原解密数据...")

        # 2. 逐行解密读取
        for line in f_in:
            read_chars += len(line)
            block_b32 = line.strip()
            if not block_b32:
                continue
                
            percent = int(15 + (read_chars / total_chars) * 65)
            percent = min(percent, 80)
            
            if progress_callback:
                progress_callback(percent, f"⚡ 正在还原并解密数据分块 ({percent}%)...")

            block_b32_upper = block_b32.upper()
            if len(block_b32_upper) % 8:
                block_b32_upper += '=' * (8 - (len(block_b32_upper) % 8))
                
            combined = base64.b32decode(block_b32_upper)
            nonce = combined[:12]
            ciphertext = combined[12:]
            
            decrypted_block = aesgcm.decrypt(nonce, ciphertext, None)
            payload_data.extend(decrypted_block)
            
        # 3. 解析元数据包 [1字节长度] + [文件名] + [压缩数据]
        if progress_callback:
            progress_callback(85, "📂 正在解析源文件名与元数据...")
            
        name_len = payload_data[0]
        original_name = payload_data[1:1+name_len].decode('utf-8')
        compressed_data = payload_data[1+name_len:]
        
        # 4. 智能判断与纠正输出路径
        # 提取原文件的后缀名（例如：".jpg"）
        _, orig_ext = os.path.splitext(original_name)
        
        final_output_path = output_dir_or_file
        
        # 情况 A：用户没填，或者填的是一个已存在的文件夹
        if not final_output_path or os.path.isdir(final_output_path):
            final_output_path = os.path.join(final_output_path or "", original_name)
        
        # 情况 B：用户指定了具体的文件路径，但我们需要检查其后缀
        else:
            # 拆分用户指定的路径，获取用户写的后缀
            user_base, user_ext = os.path.splitext(final_output_path)
            
            # 如果用户没写后缀，或者写的后缀与原文件后缀（不区分大小写）不一致
            if not user_ext or user_ext.lower() != orig_ext.lower():
                # 智能纠正：强行保留用户起的文件名，但把后缀换成正确的原文件后缀
                final_output_path = user_base + orig_ext
            
        # 5. 解压并还原
        if progress_callback:
            progress_callback(90, f"📦 正在解压还原原始文件 -> {os.path.basename(final_output_path)}")
            
        plaintext = gzip.decompress(compressed_data)
        with open(final_output_path, 'wb') as f_out:
            f_out.write(plaintext)
            
    if progress_callback:
        progress_callback(100, f"🎉 解密成功！文件已还原为: {os.path.basename(final_output_path)}")