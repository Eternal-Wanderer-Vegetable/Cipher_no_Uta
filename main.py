# main.py
import os
import sys
import argparse
import asyncio
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Button, Input, Label, RadioSet, RadioButton, ProgressBar, Log
from crypto_core import encrypt_file, decrypt_file

# ==========================================
# 🌟 CLI 命令行模式实现
# ==========================================
def run_cli(args):
    """静默命令行模式，适合后端或自动化脚本"""
    print(f"⚡ 正在运行命令行模式...")
    try:
        if args.encrypt:
            print(f"🔒 开始加密: {args.input} -> {args.output}")
            out = encrypt_file(
                args.input, 
                args.password, 
                args.output, 
                progress_callback=lambda p, m: print(f"[{int(p*100)}%] {m}")
            )
            print(f"🎉 加密成功！输出文件: {args.output}")
        elif args.decrypt:
            print(f"🔓 开始解密: {args.input} -> {args.output}")
            out = decrypt_file(
                args.input, 
                args.password, 
                args.output, 
                progress_callback=lambda p, m: print(f"[{int(p*100)}%] {m}")
            )
            print(f"🎉 解密成功！输出位置: {args.output}")
        sys.exit(0)
    except Exception as e:
        print(f"❌ 运行出错: {str(e)}", file=sys.stderr)
        sys.exit(1)

# ==========================================
# 📺 TUI 界面模式实现
# ==========================================
class MainApp(App):
    """加密伪装传输工具"""
    CSS = """
    Screen { align: center middle; background: $background; }
    #main-container { width: 85; height: 35; border: double $accent; padding: 1 2; background: $surface; }
    .title { text-align: center; width: 100%; text-style: bold; color: $accent; margin-bottom: 1; }
    .section-label { text-style: bold; margin-top: 1; color: $primary; }
    RadioSet { layout: horizontal; background: transparent; border: none; height: 3; margin-bottom: 1; }
    Input { margin-bottom: 1; border: tall $primary-darken-3; }
    Input:focus { border: tall $accent; }
    Button { width: 100%; margin-top: 1; height: 3; background: $accent; color: $text; text-style: bold; }
    ProgressBar { margin-top: 1; margin-bottom: 1; width: 100%; }
    ProgressBar > Bar { width: 1fr; }
    Log { height: 4; border: solid $primary-darken-2; background: $panel; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main-container"):
            yield Label("🔒 Cipher_no_Uta —— 文件伪装加密套件", classes="title")
            
            yield Label("🎯 请选择操作模式:", classes="section-label")
            with RadioSet(id="mode-select"):
                yield RadioButton("文件加密 (伪装为文本)", id="mode-encrypt", value=True)
                yield RadioButton("文件解密 (还原原文件)", id="mode-decrypt")
                
            yield Label("📂 原始文件/文件夹路径 (支持拖入):", classes="section-label")
            yield Input(placeholder="拖入或输入需要处理的文件/文件夹路径...", id="input-path")
            
            yield Label("💾 保存输出路径 (选填，不填则默认输出到同目录下):", classes="section-label")
            yield Input(placeholder="拖入或输入保存文件的路径或文件夹...", id="output-path")
            
            yield Label("🔑 安全对称密码 (请输入或从协商助手复制):", classes="section-label")
            yield Input(placeholder="输入加解密密码...", id="crypto-password", password=True)
            
            yield Button("立即开始执行 🚀", id="btn-run", variant="success")
            yield ProgressBar(show_eta=False, show_percentage=True)
            yield Log(id="log-box")
        yield Footer()

    def on_mount(self) -> None:
        self.progress_bar = self.query_one(ProgressBar)
        self.log_box = self.query_one("#log-box", Log)
        self.progress_bar.update(total=100, progress=0)
        self.log_box.write_line("系统初始化成功。准备就绪。")
        
        # 记录上一次的文本值
        self.last_values = {"input-path": "", "output-path": ""}
        # 🚀 新增：防重入锁，阻止代码修改 value 时重复触发判定
        self.is_updating = False

    # 🚀 终极物理切片：无死角粉碎任何路径粘连和拼接
    def on_input_changed(self, event: Input.Changed) -> None:
        if self.is_updating:
            return

        widget = event.input
        widget_id = widget.id
        
        if widget_id not in ["input-path", "output-path"]:
            return

        val = widget.value.strip()
        last_val = self.last_values.get(widget_id, "")
        
        if val == last_val or not val:
            return

        import re
        clean_path = val

        # 1. 针对 Windows 路径：查找所有盘符「X:\」或「X:/」的物理起始位置
        drive_matches = list(re.finditer(r'[A-Za-z]:[\\/]', val))
        if drive_matches:
            last_start = drive_matches[-1].start()
            # 如果存在多个盘符，或者唯一的盘符不在最开头（说明前面粘连了旧路径或脏数据）
            if len(drive_matches) > 1 or last_start > 0:
                clean_path = val[last_start:].strip('"').strip()

        # 2. 针对 Unix 路径：如果存在多个绝对路径且有空格前缀
        elif val.startswith('/'):
            unix_matches = list(re.finditer(r'\s+/[^/\s]', val))
            if unix_matches:
                last_start = unix_matches[-1].start()
                clean_path = val[last_start:].strip().strip('"').strip()

        # 🚀 核心判定：如果清洗后的路径与当前框内不一致，说明发生了“拼接污染”，立刻覆盖
        if clean_path != val:
            self.is_updating = True
            widget.value = clean_path
            self.is_updating = False
            
            # 同步状态，打印日志
            self.last_values[widget_id] = clean_path
            self.log_box.write_line(f"🧹 检测到路径拼接，已自动清空历史并替换为最新路径。")
            return

        # 正常手动修改时，只更新历史值
        self.last_values[widget_id] = val
        
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            is_encrypt = self.query_one("#mode-encrypt", RadioButton).value
            input_path = self.query_one("#input-path", Input).value.strip().strip('"')
            output_path = self.query_one("#output-path", Input).value.strip().strip('"')
            password = self.query_one("#crypto-password", Input).value.strip()

            if not input_path or not os.path.exists(input_path):
                self.log_box.write_line("❌ 错误：原始路径不存在或为空！")
                return
            if not password:
                self.log_box.write_line("❌ 错误：密码不能为空！")
                return

            # ---- 🚀 智能默认路径与严格后缀处理（加密强制为 .txt） ----
            if is_encrypt:
                dir_name = os.path.dirname(input_path)
                base_name = os.path.basename(input_path)
                name_without_ext, _ = os.path.splitext(base_name)
                
                if not output_path:
                    output_path = os.path.join(dir_name, name_without_ext + ".txt")
                elif os.path.isdir(output_path):
                    output_path = os.path.join(output_path, name_without_ext + ".txt")
                else:
                    # 🚀 强制将用户自定义的任何后缀替换为正确的 .txt 后缀
                    user_base, _ = os.path.splitext(output_path)
                    output_path = user_base + ".txt"

            self.run_worker(self.execute_crypto(is_encrypt, input_path, output_path, password))

    async def execute_crypto(self, is_encrypt, input_path, output_path, password):
        self.progress_bar.progress = 0
        self.log_box.write_line("⏳ 任务开始...")
        
        def update_progress(percent_or_ratio, msg):
            val = int(percent_or_ratio * 100) if percent_or_ratio <= 1.0 else int(percent_or_ratio)
            self.call_from_thread(lambda: self.progress_bar.update(progress=val))
            self.call_from_thread(self.log_box.write_line, msg)

        try:
            loop = asyncio.get_running_loop()

            if is_encrypt:
                is_dir = os.path.isdir(input_path)
                target_type = "文件夹" if is_dir else "文件"
                self.log_box.write_line(f"📦 检测到输入为{target_type}，准备开始加密...")
                
                # 扔进独立线程执行
                await loop.run_in_executor(
                    None, 
                    encrypt_file, 
                    input_path, 
                    password, 
                    output_path, 
                    update_progress
                )
                self.log_box.write_line(f"🎉 加密伪装成功！输出文件: {output_path}")
            else:
                self.log_box.write_line("🔑 正在提取元数据并执行解密...")
                
                # 扔进独立线程执行
                await loop.run_in_executor(
                    None, 
                    decrypt_file, 
                    input_path, 
                    password, 
                    output_path, 
                    update_progress
                )
                self.log_box.write_line(f"🎉 任务处理完毕！")
        except Exception as e:
            self.log_box.write_line(f"❌ 运行失败: {str(e)}")

# ==========================================
# ⚙️ 入口判断逻辑 (CLI 与 TUI 的分水岭)
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cipher_no_Uta 文件加解密工具命令行接口")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", action="store_true", help="加密模式")
    group.add_argument("-d", "--decrypt", action="store_true", help="解密模式")
    
    parser.add_argument("-i", "--input", type=str, help="输入文件或文件夹路径")
    parser.add_argument("-o", "--output", type=str, default="", help="输出保存路径")
    parser.add_argument("-p", "--password", type=str, help="加解密密码")

    if len(sys.argv) > 1:
        args = parser.parse_args()
        if not args.input or not args.password:
            parser.print_help()
            sys.exit(1)
        run_cli(args)
    else:
        app = MainApp()
        app.run()