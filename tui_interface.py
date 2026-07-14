# tui_interface.py
import os
import threading
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Button, Input, Label, RadioSet, RadioButton, Log

# 🚀 导入刚才拆分出去的核心加解密逻辑
from crypto_core import encrypt_file, decrypt_file

class CryptoApp(App):
    """一个美观直观的加密伪装传输工具 TUI 界面"""
    BINDINGS = [
        ("q", "quit", "退出程序"),
        ("ctrl+c", "quit", "退出")
    ]
    
    CSS = """
    Screen { align: center middle; background: $background; }
    #main-container { width: 80; height: 32; border: double $primary; padding: 1 2; background: $surface; }
    .title { text-align: center; width: 100%; text-style: bold; color: $accent; margin-bottom: 1; }
    .section-label { text-style: bold; margin-top: 1; color: $primary; }
    Input { margin-bottom: 1; border: tall $primary-darken-3; }
    Input:focus { border: tall $accent; }
    #radio-group { border: none; height: 3; margin-bottom: 1; }
    #btn-run { width: 100%; margin-top: 1; background: $accent; color: $text; text-style: bold; }
    Log { height: 6; border: solid $primary-darken-2; background: $panel; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            yield Label("🔐 加密伪装传输工具 v2.1", classes="title")
            
            yield Label("📁 请选择操作模式:", classes="section-label")
            with RadioSet(id="radio-group"):
                yield RadioButton("加密文件 (Encrypt)", value=True, id="mode-encrypt")
                yield RadioButton("解密还原 (Decrypt)", id="mode-decrypt")
                
            yield Label("📥 输入文件路径 (源文件):", classes="section-label")
            yield Input(placeholder="请输入或拖入源文件路径...", id="input-path")
            
            yield Label("📤 输出文件路径 (目标路径):", classes="section-label")
            yield Input(placeholder="请输入输出文件路径...", id="output-path")
            
            yield Label("🔑 访问密码 (输入时自动隐蔽):", classes="section-label")
            yield Input(placeholder="请输入强密码...", password=True, id="password")
            
            yield Button("开始执行任务 ⚡", id="btn-run", variant="primary")
            yield Log(id="log-box")
        yield Footer()

    def on_mount(self) -> None:
        self.log_box = self.query_one("#log-box", Log)
        self.log_box.write_line("系统就绪。请填写上方参数，然后点击[开始执行]按钮。")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        input_widget = self.query_one("#input-path", Input)
        output_widget = self.query_one("#output-path", Input)
        if event.pressed.id == "mode-encrypt":
            input_widget.placeholder = "请输入或拖入源文件路径... (如: photo.jpg)"
            output_widget.placeholder = "请输入输出伪装文本路径... (如: secret.txt)"
        else:
            input_widget.placeholder = "请输入或拖入伪装文本路径... (如: secret.txt)"
            output_widget.placeholder = "请输入输出还原文件路径... (如: photo_restore.jpg)"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            is_encrypt = self.query_one("#mode-encrypt", RadioButton).value
            input_path = self.query_one("#input-path", Input).value.strip()
            output_path = self.query_one("#output-path", Input).value.strip()
            password = self.query_one("#password", Input).value
            
            if not input_path or not output_path or not password:
                self.log_box.write_line("❌ 错误: 请完整填写输入路径、输出路径和密码！")
                return
            if not os.path.exists(input_path):
                self.log_box.write_line(f"❌ 错误: 输入路径文件不存在 -> {input_path}")
                return

            event.button.disabled = True
            self.log_box.write_line("⏳ 任务开始，正在后台处理中...")
            
            def worker():
                try:
                    if is_encrypt:
                        self.log_box.write_line(f"🔐 正在加密: {input_path} ...")
                        encrypt_file(input_path, password, output_path)
                        self.log_box.write_line(f"✓ 加密成功！已保存至: {output_path}")
                    else:
                        self.log_box.write_line(f"🔓 正在解密: {input_path} ...")
                        decrypt_file(input_path, password, output_path)
                        self.log_box.write_line(f"✓ 解密成功！已保存至: {output_path}")
                except Exception as e:
                    self.log_box.write_line(f"❌ 操作失败: {str(e)}")
                finally:
                    self.app.call_from_thread(self.enable_run_button)

            threading.Thread(target=worker, daemon=True).start()

    def enable_run_button(self):
        self.query_one("#btn-run", Button).disabled = False