# share_app.py
import os
import base64
import pyperclip
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Header, Footer, Button, Input, Label, Log, Checkbox
from key_exchange_core import generate_key_pair, agree_shared_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 本地秘钥持久化保存文件名
CREDENTIALS_FILE = "server_credentials.dat"

class ShareApp(App):
    """密钥安全协商小程序 - 增设服务器口令锁定版"""
    CSS = """
    Screen { align: center middle; background: $background; }
    #main-container { width: 80; height: 38; border: double $accent; padding: 1 2; background: $surface; }
    .title { text-align: center; width: 100%; text-style: bold; color: $accent; margin-bottom: 1; }
    .section-label { text-style: bold; margin-top: 1; color: $primary; }
    
    .row-layout { height: 4; margin-bottom: 1; }
    .row-layout Input { width: 3fr; }
    .row-layout Button { width: 1fr; margin-left: 2; height: 3; }
    
    /* 🚀 按钮容器布局 */
    #action-bar { height: 3; margin-top: 1; margin-bottom: 1; }
    
    /* 常态（未锁定）：带有一层隐形的占位边框，防止切换时产生物理像素抖动 */
    #chk-lock { 
        width: 1fr; 
        height: 3; 
        background: $panel; 
        border: tall transparent; 
        content-align: center middle; 
    }
    
    /* 🎨 特效触发（锁定时）：边框变为安全绿 */
    #chk-lock.is-locked {
        border: tall $success;
    }
    
    /* 🎨 特效触发（锁定时）：文字也变成绿色并加粗 */
    #chk-lock.is-locked > .toggle--label {
        color: $success;
        text-style: bold;
    }
    
    /* 移除聚焦、点击时默认的蓝底高亮效果，保持常态配色 */
    #chk-lock:focus { 
        background: $panel; 
        color: $text; 
    }
    
    #chk-lock:focus > .toggle--label { 
        background: transparent !important; 
        color: $text; 
    }
    
    #chk-lock:focus > .toggle--button { 
        background: transparent !important; 
        color: $accent; 
    }
    
    /* 锁定时获得焦点：文本保持绿色 */
    #chk-lock.is-locked:focus > .toggle--label {
        color: $success;
    }
    
    #btn-agree { width: 1fr; margin-left: 2; height: 3; background: $accent; color: $text; text-style: bold; }
    
    Input { margin-bottom: 1; border: tall $primary-darken-3; }
    Input:focus { border: tall $accent; }
    #my-pub-key { background: $panel; border: dashed $accent; }
    #final-key { background: $panel; border: double $success; color: $success; text-style: bold; }
    
    Log { height: 4; border: solid $primary-darken-2; background: $panel; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main-container"):
            yield Label("🤝 密钥安全无感协商助手", classes="title")
            
            yield Label("📢 你的公开配对口令 (发送给对方):", classes="section-label")
            with Horizontal(classes="row-layout"):
                yield Input(disabled=True, id="my-pub-key")
                yield Button("👉 复制口令", id="btn-copy-my", variant="primary")
            
            yield Label("📥 粘贴对方的配对口令:", classes="section-label")
            yield Input(placeholder="在此处粘贴对方发给你的口令...", id="peer-pub-key")
            
            # 🚀 修复点 1 & 2：将锁定复选框与合成按钮并排，各占一半
            with Horizontal(id="action-bar"):
                yield Checkbox("🔒 锁定为固定静态口令", id="chk-lock")
                yield Button("合成绝密对称密码 ⚡", id="btn-agree", variant="success")
            
            yield Label("🔑 最终合成的对称密码 (可在此直接复制):", classes="section-label")
            with Horizontal(classes="row-layout"):
                yield Input(disabled=True, placeholder="等待双方口令配对...", id="final-key")
                yield Button("👉 复制密钥", id="btn-copy-final", variant="primary", disabled=True)
                
            yield Log(id="log-box")
        yield Footer()

    def on_mount(self) -> None:
        self.log_box = self.query_one("#log-box", Log)
        self.chk_lock = self.query_one("#chk-lock", Checkbox)
        
        # 尝试加载固定口令
        if os.path.exists(CREDENTIALS_FILE):
            self.chk_lock.value = True
            # 🚀 新增：初始化时如果已锁定，直接施加绿色高亮特效
            self.chk_lock.add_class("is-locked")
            self.load_locked_key()
        else:
            self.generate_fresh_key()

    def generate_fresh_key(self):
        """生成临时随机公私钥对"""
        self.private_key, my_public_str = generate_key_pair()
        self.query_one("#my-pub-key", Input).value = my_public_str
        self.log_box.write_line("✓ 随机临时密钥已初始化！(高安全性，每次关闭均会重置)")

    def load_locked_key(self):
        """从本地文件读取静态固定的私钥"""
        try:
            with open(CREDENTIALS_FILE, 'rb') as f:
                pem_data = f.read()
            self.private_key = serialization.load_pem_private_key(pem_data, password=None)
            
            # 生成与之对应的精简公钥口令
            public_key = self.private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
            my_public_str = base64.b32encode(public_bytes).decode('utf-8').lower().replace('=', '')
            self.query_one("#my-pub-key", Input).value = my_public_str
            self.log_box.write_line("✓ 🔒 已成功载入本地固定的静态服务端密钥对！")
        except Exception as e:
            self.log_box.write_line(f"❌ 载入静态密钥失败，自动创建新密钥: {str(e)}")
            self.generate_fresh_key()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """当用户手动勾选/取消勾选 锁定 选项时"""
        if event.checkbox.id == "chk-lock":
            if event.value: # 启用锁定
                # 🚀 开启特效：加绿框
                self.chk_lock.add_class("is-locked")
                try:
                    pem = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    with open(CREDENTIALS_FILE, 'wb') as f:
                        f.write(pem)
                    self.log_box.write_line("💾 密钥已本地持久化！以后启动将保持该固定口令。")
                except Exception as e:
                    self.log_box.write_line(f"❌ 密钥保存失败: {str(e)}")
            else: # 取消锁定
                # 🚀 关闭特效：移除绿框
                self.chk_lock.remove_class("is-locked")
                if os.path.exists(CREDENTIALS_FILE):
                    try:
                        os.remove(CREDENTIALS_FILE)
                        self.log_box.write_line("🗑️ 已清除本地静态密钥。重新生成随机密钥...")
                        self.generate_fresh_key()
                    except Exception as e:
                        self.log_box.write_line(f"❌ 清理历史密钥失败: {str(e)}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-copy-my":
            my_key = self.query_one("#my-pub-key", Input).value
            if my_key:
                pyperclip.copy(my_key)
                self.log_box.write_line("📋 你的公开配对口令已复制到系统剪贴板！")
                self.notify("口令已复制！")
                
        elif event.button.id == "btn-copy-final":
            final_key = self.query_one("#final-key", Input).value
            if final_key:
                pyperclip.copy(final_key)
                self.log_box.write_line("📋 对称密码已复制，可在加解密主程序中直接使用！")
                self.notify("密钥已复制！")

        elif event.button.id == "btn-agree":
            peer_key = self.query_one("#peer-pub-key", Input).value.strip()
            if not peer_key:
                self.log_box.write_line("❌ 错误：请先输入对方的口令！")
                return
            
            try:
                shared_password = agree_shared_key(self.private_key, peer_key)
                final_key_input = self.query_one("#final-key", Input)
                final_key_input.value = shared_password
                
                self.query_one("#btn-copy-final", Button).disabled = False
                self.log_box.write_line(f"🎉 密钥成功合成！")
                self.notify("对称密码合成成功！", severity="information")
            except Exception as e:
                self.log_box.write_line(f"❌ 合成失败: {str(e)}")

if __name__ == "__main__":
    app = ShareApp()
    app.run()