# tui_interface.py
# tui_interface.py
import os
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Button, Input, Label, RadioSet, RadioButton, Log, ProgressBar

# 导入刚才修改完支持回调的核心算法
from crypto_core import encrypt_file, decrypt_file

class CryptoApp(App):
    """支持进度条和精细排查的高级 TUI 界面"""
    BINDINGS = [
        ("q", "quit", "退出程序"),
        ("ctrl+c", "quit", "退出")
    ]
    
    CSS = """
    Screen { align: center middle; background: $background; }
    #main-container { width: 80; height: 35; border: double $primary; padding: 1 2; background: $surface; }
    .title { text-align: center; width: 100%; text-style: bold; color: $accent; margin-bottom: 1; }
    .section-label { text-style: bold; margin-top: 1; color: $primary; }
    Input { margin-bottom: 1; border: tall $primary-darken-3; }
    Input:focus { border: tall $accent; }
    #radio-group { border: none; height: 3; margin-bottom: 1; }
    #btn-run { width: 100%; margin-top: 1; background: $accent; color: $text; text-style: bold; }
    ProgressBar { margin-top: 1; margin-bottom: 1; width: 100%; }
    Log { height: 6; border: solid $primary-darken-2; background: $panel; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            yield Label("🔐 加密伪装传输工具 v2.2", classes="title")
            
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
            
            # 🚀 进度条组件（初始化为不可见，或者总进度 100）
            yield ProgressBar(total=100, show_eta=False, id="crypto-progress")
            
            yield Log(id="log-box")
        yield Footer()

    def on_mount(self) -> None:
        self.log_box = self.query_one("#log-box", Log)
        self.progress_bar = self.query_one("#crypto-progress", ProgressBar)
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

    # ============ 🚀 线程安全的多线程消息通信 ============
    def update_ui_progress(self, percent: int, message: str) -> None:
        """这个方法保证在 Textual 主事件循环线程内执行，绝对不会卡死！"""
        self.log_box.write_line(message)
        self.progress_bar.progress = percent  # 直接修改进度条比例

    def enable_ui_after_job(self) -> None:
        """解密/加密结束，恢复按钮可点"""
        self.query_one("#btn-run", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            is_encrypt = self.query_one("#mode-encrypt", RadioButton).value
            input_path = self.query_one("#input-path", Input).value.strip()
            output_path = self.query_one("#output-path", Input).value.strip()

            # ---- 🚀 新增：智能路径补全逻辑 ----
            if os.path.isdir(output_path):
            # 如果是加密模式，自动在文件夹后追加 "secret.txt"
                if is_encrypt:
                    output_path = os.path.join(output_path, "secret.txt")
                # 如果是解密模式，自动在文件夹后追加 "restored_file" (用户可以之后自己改后缀)
                else:
                    output_path = os.path.join(output_path, "restored_file")
            # ---------------------------------

            password = self.query_one("#password", Input).value
            
            if not input_path or not output_path or not password:
                self.log_box.write_line("❌ 错误: 请完整填写输入路径、输出路径和密码！")
                return
            if not os.path.exists(input_path):
                self.log_box.write_line(f"❌ 错误: 输入路径文件不存在 -> {input_path}")
                return

            event.button.disabled = True
            self.progress_bar.progress = 0  # 进度归零
            self.log_box.write_line("⏳ 任务正式启动...")

            # 🚀 创建进度回调桥梁
            def tui_callback(percent, message):
                # 核心机制：利用 call_from_thread 把工作进度打包发送到主线程安全的方法中更新
                self.app.call_from_thread(self.update_ui_progress, percent, message)

            def do_crypto_work():
                try:
                    if is_encrypt:
                        encrypt_file(input_path, password, output_path, progress_callback=tui_callback)
                    else:
                        decrypt_file(input_path, password, output_path, progress_callback=tui_callback)
                except Exception as e:
                    self.app.call_from_thread(self.update_ui_progress, 0, f"❌ 操作崩溃: {str(e)}")
                finally:
                    self.app.call_from_thread(self.enable_ui_after_job)

            # 启动 Textual 安全的工作线程
            self.run_worker(do_crypto_work, thread=True)