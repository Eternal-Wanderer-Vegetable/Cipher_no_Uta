# main.py
#!/usr/bin/env python3
"""
加密伪装传输工具 - 模块化入口版
"""
from tui_interface import CryptoApp

def main():
    # 实例并启动 TUI 界面
    app = CryptoApp()
    app.run()

if __name__ == "__main__":
    main()