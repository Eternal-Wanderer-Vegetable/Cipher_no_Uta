# test_debug.py
import time
import os
import sys

# 尝试导入核心算法
try:
    import crypto_core
except ImportError:
    print("❌ 错误：未能在当前目录找到 crypto_core.py！")
    sys.exit(1)

def run_debug_test(test_file_path, password):
    print("================ 🔍 开始密码学核心性能与逻辑排查 ================")
    
    if not os.path.exists(test_file_path):
        print(f"❌ 错误：找不到用于测试的源文件 {test_file_path}")
        return

    file_size = os.path.getsize(test_file_path)
    print(f"[1] 测试文件: {test_file_path} (大小: {file_size:,} 字节 / ~{file_size/1024:.2f} KB)")
    
    # ------------------ 阶段 1：派生密钥排查 ------------------
    print("\n[2] 正在测试密钥派生 (PBKDF2)...")
    start_time = time.time()
    try:
        salt = os.urandom(16)
        _ = crypto_core.derive_key(password, salt)
        kdf_time = time.time() - start_time
        print(f"   ⚡ 密钥派生耗时: {kdf_time:.4f} 秒 (正常情况应在 0.1 ~ 0.5 秒左右)")
    except Exception as e:
        print(f"   ❌ 密钥派生阶段崩溃: {e}")
        return

    # ------------------ 阶段 2：执行完整加密排查 ------------------
    output_txt = "debug_output.txt"
    print(f"\n[3] 正在调用 encrypt_file 进行加密...")
    start_time = time.time()
    try:
        crypto_core.encrypt_file(test_file_path, password, output_txt)
        enc_time = time.time() - start_time
        print(f"   ⚡ 加密函数执行总耗时: {enc_time:.4f} 秒")
        
        if os.path.exists(output_txt):
            out_size = os.path.getsize(output_txt)
            print(f"   ✓ 生成伪装文件成功: {output_txt} (大小: {out_size:,} 字节)")
        else:
            print("   ❌ 警告：加密函数虽然结束，但未生成输出文件！")
    except Exception as e:
        print(f"   ❌ 加密阶段崩溃或卡死位置报错: {e}")
        return

    # ------------------ 阶段 3：执行完整解密排查 ------------------
    restore_file = "debug_restore.jpg"
    print(f"\n[4] 正在调用 decrypt_file 进行解密...")
    start_time = time.time()
    try:
        crypto_core.decrypt_file(output_txt, password, restore_file)
        dec_time = time.time() - start_time
        print(f"   ⚡ 解密函数执行总耗时: {dec_time:.4f} 秒")
        
        if os.path.exists(restore_file):
            res_size = os.path.getsize(restore_file)
            print(f"   ✓ 还原文件成功: {restore_file} (大小: {res_size:,} 字节)")
            if res_size == file_size:
                print("   🎉 完美！还原文件与源文件大小完全一致，算法完全通过测试！")
            else:
                print("   ⚠️ 警告：还原文件存在，但大小与源文件不一致！")
        else:
            print("   ❌ 警告：解密函数虽然结束，但未生成还原文件！")
    except Exception as e:
        print(f"   ❌ 解密阶段崩溃: {e}")

if __name__ == "__main__":
    # 请确保当前目录下有一个真实的 test.jpg，或者改成你们测试用的图片路径
    TEST_IMAGE = "test.jpg" 
    TEST_PASSWORD = "Password123!"
    
    # 如果没有 test.jpg，临时创建一个 132KB 的伪文件进行测试
    if not os.path.exists(TEST_IMAGE):
        with open(TEST_IMAGE, "wb") as f:
            f.write(os.urandom(132 * 1024))
            
    run_debug_test(TEST_IMAGE, TEST_PASSWORD)