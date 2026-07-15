# key_exchange_core.py
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_key_pair():
    """1. 生成本地椭圆曲线公私钥对 (使用压缩公钥，大幅度缩短口令长度)"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # 🚀 关键修改：使用 Compressed 格式，公钥大小从 65 字节骤降至 33 字节
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    # 转换为更短的 Base32 字符串
    public_str = base64.b32encode(public_bytes).decode('utf-8').lower().replace('=', '')
    return private_key, public_str

def agree_shared_key(my_private_key, peer_public_str: str) -> str:
    """2. 结合对方的短公钥“口令”，在本地算出一致的对称密钥"""
    try:
        peer_public_str = peer_public_str.upper().strip()
        if len(peer_public_str) % 8:
            peer_public_str += '=' * (8 - (len(peer_public_str) % 8))
        peer_public_bytes = base64.b32decode(peer_public_str)
        
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_public_bytes
        )
        
        # 执行 ECDH 协商
        shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)
        
        # 使用 HKDF 派生高强度对称密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cipher-no-uta-key-exchange",
        ).derive(shared_secret)
        
        # 返回 16 位对称密钥
        return base64.b32encode(derived_key).decode('utf-8').lower().replace('=', '')[:16]
    except Exception as e:
        raise ValueError(f"口令解析失败，请确保复制了完整的口令！")