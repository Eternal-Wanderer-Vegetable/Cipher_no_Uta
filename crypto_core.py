# crypto_core.py
import os
import shutil
import struct
import tempfile
import base64
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
CHUNK_SIZE = 512 * 1024  # 512KB 分块

# 魔法字节，用于区分是文件还是文件夹
MAGIC_FILE = b"FILE_RAW"
MAGIC_DIR = b"DIR_ZIP\x00"

def derive_key(password: str, salt: bytes) -> bytes:
    """使用更安全的 Scrypt 算法从密码和 Salt 中派生密钥"""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_path: str, password: str, output_txt_path: str, progress_callback=None):
    """
    【真正流式分块加密】支持单个文件或整个文件夹
    """
    if progress_callback:
        progress_callback(0, "🔑 正在初始化...")

    is_dir = os.path.isdir(input_path)
    temp_zip = None

    try:
        # 1. 文件夹打包处理
        if is_dir:
            if progress_callback:
                progress_callback(5, "📦 正在打包压缩文件夹...")
            temp_dir = tempfile.gettempdir()
            temp_zip_base = os.path.join(temp_dir, os.path.basename(input_path.rstrip(os.sep)))
            temp_zip = shutil.make_archive(temp_zip_base, 'zip', input_path)
            encrypt_target = temp_zip
            original_name = os.path.basename(input_path)
        else:
            encrypt_target = input_path
            original_name = os.path.basename(input_path)

        # 2. 密钥派生与元数据准备
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        magic = MAGIC_DIR if is_dir else MAGIC_FILE
        name_bytes = original_name.encode('utf-8')
        name_len = len(name_bytes)

        if name_len > 255:
            raise ValueError("文件名过长，最大支持 255 字节！")

        payload_header = magic + bytes([name_len]) + name_bytes
        target_size = os.path.getsize(encrypt_target)
        
        if progress_callback:
            progress_callback(15, "🔐 开始分块加密流式写入...")

        # 3. 流式分块加密写入文本
        with open(encrypt_target, 'rb') as f_in, open(output_txt_path, 'w', encoding='utf-8') as f_out:
            # 强制后缀纠偏：确保输出一定是 .txt 结尾
            salt_b32 = base64.b32encode(salt).decode('ascii').lower().replace('=', '')
            f_out.write(salt_b32 + "\n")
            
            header_processed = False
            read_bytes = 0
            last_percent = -1
            
            while True:
                if not header_processed:
                    file_block = f_in.read(CHUNK_SIZE)
                    read_bytes += len(file_block)
                    block = payload_header + file_block
                    header_processed = True
                else:
                    block = f_in.read(CHUNK_SIZE)
                    read_bytes += len(block)
                    if not block:
                        break
                
                # 计算平滑进度 (15% - 95%)
                if target_size > 0:
                    percent = int(15 + (read_bytes / target_size) * 80)
                    percent = min(percent, 95)
                else:
                    percent = 50
                
                if progress_callback and percent != last_percent:
                    progress_callback(percent, f"⚡ 正在加密并转换数据分块 ({percent}%)...")
                    last_percent = percent

                nonce = os.urandom(NONCE_SIZE)
                ciphertext = aesgcm.encrypt(nonce, block, None)
                combined = nonce + ciphertext
                
                block_b32 = base64.b32encode(combined).decode('ascii').lower().replace('=', '')
                f_out.write(block_b32 + "\n")

        if progress_callback:
            progress_callback(100, "🎉 加密成功，数据流写入完毕！")

    finally:
        if temp_zip and os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except:
                pass


def decrypt_file(input_txt_path: str, password: str, output_dir_or_file: str, progress_callback=None):
    """
    【流式分块解密】包含强校验及防呆设计，解压时强制修正为正确的后缀[cite: 1]
    """
    if progress_callback:
        progress_callback(0, "🔑 正在读取并派生解密密钥...")

    total_chars = os.path.getsize(input_txt_path)
    read_chars = 0
    
    # 临时文件，解密密文暂存区
    temp_output = tempfile.NamedTemporaryFile(delete=False)
    temp_output_path = temp_output.name
    temp_output.close()

    try:
        # 第一阶段：流式解密 (占 15% - 80% 进度)[cite: 1]
        with open(input_txt_path, 'r', encoding='utf-8') as f_in, open(temp_output_path, 'wb') as f_out:
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
            
            if progress_callback:
                progress_callback(15, "🔓 开始逐行解密还原数据流...")

            header_extracted = False
            is_dir = False
            original_name = ""
            last_percent = -1
            
            for line in f_in:
                read_chars += len(line)
                block_b32 = line.strip()
                if not block_b32:
                    continue
                    
                percent = int(15 + (read_chars / total_chars) * 65)
                percent = min(percent, 80)
                
                if progress_callback and percent != last_percent:
                    progress_callback(percent, f"⚡ 正在解密还原密文 ({percent}%)...")
                    last_percent = percent

                block_b32_upper = block_b32.upper()
                if len(block_b32_upper) % 8:
                    block_b32_upper += '=' * (8 - (len(block_b32_upper) % 8))
                    
                combined = base64.b32decode(block_b32_upper)
                nonce = combined[:NONCE_SIZE]
                ciphertext = combined[NONCE_SIZE:]
                
                try:
                    decrypted_block = aesgcm.decrypt(nonce, ciphertext, None)
                except Exception:
                    raise ValueError("解密失败：密码错误或数据已被篡改！")
                
                if not header_extracted:
                    magic = decrypted_block[0:8]
                    is_dir = (magic == MAGIC_DIR)
                    name_len = decrypted_block[8]
                    original_name = decrypted_block[9:9+name_len].decode('utf-8')
                    
                    actual_data = decrypted_block[9+name_len:]
                    f_out.write(actual_data)
                    header_extracted = True
                else:
                    f_out.write(decrypted_block)

        # 🚀 4. 路径智能决议（不允许任何自定义后缀）
        _, orig_ext = os.path.splitext(original_name)  # 原始后缀，如 ".MP4" 或 ".jpg"
        final_output_path = output_dir_or_file
        
        # 情况 A：如果用户没填保存路径，或者填的是一个已存在的文件夹
        if not final_output_path or os.path.isdir(final_output_path):
            final_output_path = os.path.join(final_output_path or "", original_name)
        else:
            # 情况 B：用户输入了具体的保存路径（如 e:\...\TET.txt）
            if is_dir:
                # 如果解密出来的是文件夹，则强制不带任何类似文件的后缀
                user_base, _ = os.path.splitext(final_output_path)
                final_output_path = user_base
            else:
                # 如果解密出来的是单文件：
                # 1. 提取用户输入路径的目录部分
                user_dir = os.path.dirname(final_output_path)
                # 2. 提取用户输入的文件名，并无情地丢弃他手写的任何后缀
                user_filename = os.path.basename(final_output_path)
                user_name_without_ext, _ = os.path.splitext(user_filename)
                
                # 3. 强行拼装：[用户指定的目录] + [用户指定的文件名（无后缀）] + [原始文件的绝对真实后缀]
                # 这样即使他写了 TET.txt，也会被拆成 "TET" + ".MP4"，完美还原为 TET.MP4！
                final_output_path = os.path.join(user_dir, user_name_without_ext + orig_ext)

        # 第二阶段：还原输出与解压 (占 80% - 100% 进度)[cite: 1]
        if is_dir:
            if progress_callback:
                progress_callback(80, "📦 正在分析压缩文件夹...")
                
            if os.path.exists(final_output_path):
                final_output_path = final_output_path + "_decrypted"
                
            os.makedirs(final_output_path, exist_ok=True)
            
            with zipfile.ZipFile(temp_output_path, 'r') as zip_ref:
                file_list = zip_ref.infolist()
                total_files = len(file_list)
                last_unzip_percent = -1
                
                for idx, file_info in enumerate(file_list):
                    zip_ref.extract(file_info, final_output_path)
                    
                    if total_files > 0:
                        unzip_percent = int(80 + (idx / total_files) * 18)
                    else:
                        unzip_percent = 95
                        
                    if progress_callback and unzip_percent != last_unzip_percent:
                        progress_callback(unzip_percent, f"📦 正在解压: {file_info.filename} ({unzip_percent}%)")
                        last_unzip_percent = unzip_percent
        else:
            if progress_callback:
                progress_callback(80, "💾 正在将解密文件移动至最终位置...")
                
            total_size = os.path.getsize(temp_output_path)
            copied_size = 0
            last_copy_percent = -1
            
            with open(temp_output_path, 'rb') as f_src, open(final_output_path, 'wb') as f_dest:
                while True:
                    buf = f_src.read(CHUNK_SIZE)
                    if not buf:
                        break
                    f_dest.write(buf)
                    copied_size += len(buf)
                    
                    if total_size > 0:
                        copy_percent = int(80 + (copied_size / total_size) * 18)
                    else:
                        copy_percent = 95
                        
                    if progress_callback and copy_percent != last_copy_percent:
                        progress_callback(copy_percent, f"💾 正在写入原始文件 ({copy_percent}%)...")
                        last_copy_percent = copy_percent

        if progress_callback:
            progress_callback(100, f"🎉 还原成功！位置: {os.path.basename(final_output_path)}")
            
    finally:
        # 确保清理掉临时的解密二进制桥接文件
        if os.path.exists(temp_output_path):
            try:
                os.remove(temp_output_path)
            except:
                pass