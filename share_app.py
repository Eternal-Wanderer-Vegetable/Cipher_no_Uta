# share_app.py
import pyperclip  # 导入系统剪贴板库
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Header, Footer, Button, Input, Label, Log
from key_exchange_core import generate_key_pair, agree_shared_key

class ShareApp(App):
    """密钥安全协商小程序 - 完美终端排版版"""
    CSS = """
    Screen { align: center middle; background: $background; }
    #main-container { width: 80; height: 35; border: double $accent; padding: 1 2; background: $surface; }
    .title { text-align: center; width: 100%; text-style: bold; color: $accent; margin-bottom: 1; }
    .section-label { text-style: bold; margin-top: 1; color: $primary; }
    
    /* 🚀 修复点：移除了 % 符号，使用标准的 fr 比例和字符单位 */
    .row-layout { height: 4; margin-bottom: 1; }
    .row-layout Input { width: 3fr; }
    .row-layout Button { width: 1fr; margin-left: 2; height: 3; }
    
    Input { margin-bottom: 1; border: tall $primary-darken-3; }
    Input:focus { border: tall $accent; }
    #my-pub-key { background: $panel; border: dashed $accent; }
    #final-key { background: $panel; border: double $success; color: $success; text-style: bold; }
    #btn-agree { width: 100%; margin-top: 1; background: $accent; color: $text; text-style: bold; }
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
            
            yield Button("合成绝密对称密码 ⚡", id="btn-agree", variant="success")
            
            yield Label("🔑 最终合成的对称密码 (可在此直接复制):", classes="section-label")
            with Horizontal(classes="row-layout"):
                yield Input(disabled=True, placeholder="等待双方口令配对...", id="final-key")
                yield Button("👉 复制密钥", id="btn-copy-final", variant="primary", disabled=True)
                
            yield Log(id="log-box")
        yield Footer()

    def on_mount(self) -> None:
        self.log_box = self.query_one("#log-box", Log)
        self.log_box.write_line("正在为您初始化本地临时安全公私钥...")
        
        # 生成本地公私钥
        self.private_key, my_public_str = generate_key_pair()
        
        # 显示在禁用框中
        my_pub_input = self.query_one("#my-pub-key", Input)
        my_pub_input.value = my_public_str
        
        self.log_box.write_line("✓ 初始化完毕！口令已精简。")
        self.log_box.write_line("点击【👉 复制口令】即可发送给对方。")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # 1. 复制自己的口令
        if event.button.id == "btn-copy-my":
            my_key = self.query_one("#my-pub-key", Input).value
            if my_key:
                pyperclip.copy(my_key)
                self.log_box.write_line("📋 你的公开配对口令已成功复制到系统剪贴板！")
                self.notify("口令已复制！")
                
        # 2. 复制最终协商出来的对称密钥
        elif event.button.id == "btn-copy-final":
            final_key = self.query_one("#final-key", Input).value
            if final_key:
                pyperclip.copy(final_key)
                self.log_box.write_line("📋 最终对称密钥已成功复制到系统剪贴板！")
                self.notify("密钥已复制！")

        # 3. 点击合成按钮
        elif event.button.id == "btn-agree":
            peer_key = self.query_one("#peer-pub-key", Input).value.strip()
            if not peer_key:
                self.log_box.write_line("❌ 错误：请先输入对方的口令！")
                return
            
            try:
                # 协商密码
                shared_password = agree_shared_key(self.private_key, peer_key)
                
                # 更新至密钥文本框中，并解除“复制密钥”按钮的禁用状态
                final_key_input = self.query_one("#final-key", Input)
                final_key_input.value = shared_password
                
                self.query_one("#btn-copy-final", Button).disabled = False
                
                self.log_box.write_line(f"🎉 协商成功！专属密钥已生成在上方。")
                self.log_box.write_line("ℹ️ 点击【👉 复制密钥】即可将其运用到主加解密程序中！")
                self.notify("对称密码合成成功！", severity="information")
            except Exception as e:
                self.log_box.write_line(f"❌ 合成失败: {str(e)}")

if __name__ == "__main__":
    app = ShareApp()
    app.run()