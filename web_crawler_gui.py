import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
from lxml import etree
from urllib.parse import urlparse
import csv
import threading
import re
import time
import random
import json
import os

class WebCrawlerApp:
    def __init__(self, master):
        self.master = master
        master.title("智能网页爬虫 v2.0")
        master.geometry("1000x800")  # 调整初始窗口大小
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)
        
        # 初始化变量
        self.running = False
        self.results = []
        self.url_var_config = None
        self.current_delay = tk.IntVar(value=3)  # 随机延迟默认3秒
        
        # 创建界面组件
        self.create_widgets()
    
    def create_widgets(self):
        # 主布局容器
        main_frame = ttk.Frame(self.master)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        
        # 输入区域
        input_frame = ttk.LabelFrame(main_frame, text="爬取设置")
        input_frame.grid(row=0, column=0, sticky="ew")
        main_frame.grid_rowconfigure(0, weight=0)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # URL输入带变量替换按钮
        url_frame = ttk.Frame(input_frame)
        url_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Label(url_frame, text="目标网址:").pack(side=tk.LEFT, padx=5)
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(url_frame, text="变量替换", command=self.show_variable_dialog).pack(side=tk.RIGHT, padx=5)
        
        # 请求头设置
        header_row = 1
        headers = [
            ("User-Agent:", "user_agent_entry"),
            ("X-Requested-With:", "x_requested_with_entry"),
            ("Content-Type:", "content_type_entry"),
            ("Accept-Language:", "accept_lang_entry"),
            ("Cookie:", "cookie_entry")
        ]
        
        for i, (label_text, attr_name) in enumerate(headers):
            ttk.Label(input_frame, text=label_text).grid(row=header_row+i, column=0, sticky="w", padx=5)
            # 创建对应组件
            if i == 4:  # Cookie输入框特殊处理
                entry_widget = tk.Text(input_frame, width=50, height=3)
                entry_widget.grid(row=header_row+i, column=1, padx=5, pady=2, sticky="ew")
            else:
                entry_widget = ttk.Entry(input_frame, width=50)
                entry_widget.grid(row=header_row+i, column=1, padx=5, pady=2, sticky="ew")
            
            # 设置实例属性
            # 设置实例属性
            setattr(self, attr_name, entry_widget)
            
            # 初始化默认值
            if i == 0:
                entry_widget.insert(0, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            elif i == 1:
                entry_widget.insert(0, "XMLHttpRequest")
            elif i == 2:
                entry_widget.insert(0, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            elif i == 3:
                entry_widget.insert(0, "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7")

        # HTTPS设置
        ssl_row = header_row + len(headers) + 1
        ttk.Separator(input_frame, orient='horizontal').grid(row=ssl_row, column=0, columnspan=2, sticky="ew", pady=10)
        
        ttk.Label(input_frame, text="SSL验证:").grid(row=ssl_row+1, column=0, sticky="w", padx=5)
        self.ssl_verify = tk.BooleanVar(value=True)
        ttk.Checkbutton(input_frame, variable=self.ssl_verify).grid(row=ssl_row+1, column=1, sticky="w")
        
        # 客户端证书设置
        cert_rows = [
            ("客户端证书:", "client_cert_entry"),
            ("客户端密钥:", "client_key_entry")
        ]
        
        for i, (label_text, attr_name) in enumerate(cert_rows):
            row = ssl_row + 2 + i
            ttk.Label(input_frame, text=label_text).grid(row=row, column=0, sticky="w", padx=5)
            entry_widget = ttk.Entry(input_frame, width=40)
            entry_widget.grid(row=row, column=1, padx=5, pady=2, sticky="w")
            ttk.Button(input_frame, text="浏览...", command=self.browse_cert if i == 0 else self.browse_key).grid(row=row, column=1, sticky="e")
            setattr(self, ['client_cert_entry', 'client_key_entry'][i], entry_widget)

        # 自定义请求头
        custom_header_row = ssl_row + 4
        ttk.Separator(input_frame, orient='horizontal').grid(row=custom_header_row, column=0, columnspan=2, sticky="ew", pady=10)
        
        ttk.Label(input_frame, text="其他请求头:").grid(row=custom_header_row+1, column=0, sticky="w", padx=5)
        self.custom_headers_entry = tk.Text(input_frame, width=50, height=3)
        self.custom_headers_entry.grid(row=custom_header_row+1, column=1, padx=5, pady=2, sticky="ew")
        self.custom_headers_entry.insert(tk.END, "Referer: https://www.example.com/\nAccept-Encoding: gzip, deflate, br")

        # XPath设置（加长输入框）
        xpath_frame = ttk.LabelFrame(input_frame, text="内容提取设置")
        xpath_frame.grid(row=custom_header_row+2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        ttk.Label(xpath_frame, text="XPath表达式:").grid(row=0, column=0, sticky="w", padx=5)
        self.xpath_entry = ttk.Entry(xpath_frame, width=70)
        self.xpath_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew", columnspan=4)
        ttk.Label(xpath_frame, text="示例: //div[@class='content']/h1").grid(row=1, column=1, columnspan=2, sticky="w")

        # 控制按钮区域
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, sticky="ew", pady=5)
        main_frame.grid_rowconfigure(1, weight=0)
        
        # 循环次数设置
        ttk.Label(control_frame, text="循环次数:").pack(side=tk.LEFT, padx=5)
        self.loop_count = ttk.Spinbox(control_frame, from_=1, to=100, width=5)
        self.loop_count.pack(side=tk.LEFT, padx=5)
        self.loop_count.set(1)
        
        # 操作按钮
        self.start_btn = ttk.Button(control_frame, text="开始爬取", command=self.start_crawling)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(control_frame, text="停止", state=tk.DISABLED, command=self.stop_crawling)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # 随机延迟设置
        delay_frame = ttk.Frame(control_frame)
        delay_frame.pack(side=tk.RIGHT, padx=10)
        ttk.Label(delay_frame, text="随机延迟(秒):").pack(side=tk.LEFT)
        self.delay_scale = ttk.Scale(delay_frame, from_=0, to=10, variable=self.current_delay)
        self.delay_scale.pack(side=tk.LEFT, padx=5)
        self.delay_label = ttk.Label(delay_frame, text="3")
        self.delay_label.pack(side=tk.LEFT)
        self.current_delay.trace_add("write", self.update_delay_label)
        
        # 保存按钮
        self.save_btn = ttk.Button(control_frame, text="保存结果", command=self.save_results)
        self.save_btn.pack(side=tk.RIGHT, padx=5)

        # 进度显示
        progress_frame = ttk.LabelFrame(main_frame, text="进度信息")
        progress_frame.grid(row=2, column=0, sticky="ew", pady=5)
        main_frame.grid_rowconfigure(2, weight=0)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=5, pady=2)
        self.status_label = ttk.Label(progress_frame, text="准备就绪")
        self.status_label.pack(fill=tk.X, padx=5)

        # 结果展示区域
        result_frame = ttk.LabelFrame(main_frame, text="爬取结果")
        result_frame.grid(row=3, column=0, sticky="nsew", pady=5)
        main_frame.grid_rowconfigure(3, weight=1)
        
        self.tree = ttk.Treeview(result_frame, columns=("内容"), show="headings")
        self.tree.heading("内容", text="内容")
        self.tree.column("内容", width=900)  # 加宽结果列
        
        vsb = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(result_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, columnspan=2, sticky="ew")
        
        result_frame.grid_rowconfigure(0, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)
        
        # 清屏按钮
        clear_btn = ttk.Button(result_frame, text="清空结果", command=self.clear_results)
        clear_btn.grid(row=2, column=0, sticky="e", padx=5, pady=5)

        # 加载设置
        self.load_settings()

    def browse_cert(self):
        """选择客户端证书文件"""
        filepath = filedialog.askopenfilename(title="选择客户端证书", filetypes=[("PEM 文件", "*.pem")])
        if filepath:
            self.client_cert_entry.delete(0, tk.END)
            self.client_cert_entry.insert(0, filepath)

    def browse_key(self):
        """选择客户端密钥文件"""
        filepath = filedialog.askopenfilename(title="选择客户端密钥", filetypes=[("PEM 文件", "*.pem")])
        if filepath:
            self.client_key_entry.delete(0, tk.END)
            self.client_key_entry.insert(0, filepath)

    def update_delay_label(self, *args):
        """更新延迟时间显示"""
        self.delay_label.config(text=str(self.current_delay.get()))

    def show_variable_dialog(self):
        """显示变量设置对话框"""
        dialog = tk.Toplevel(self.master)
        dialog.title("网址变量设置")
        
        # 变量配置控件
        ttk.Label(dialog, text="变量格式示例: https://example.com/page/{page}").grid(row=0, column=0, columnspan=2, padx=5, pady=2)
        
        ttk.Label(dialog, text="变量名:").grid(row=1, column=0, sticky="w", padx=5)
        var_name_entry = ttk.Entry(dialog)
        var_name_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(dialog, text="起始值:").grid(row=2, column=0, sticky="w", padx=5)
        start_entry = ttk.Entry(dialog)
        start_entry.grid(row=2, column=1, padx=5, pady=2)
        
        ttk.Label(dialog, text="结束值:").grid(row=3, column=0, sticky="w", padx=5)
        end_entry = ttk.Entry(dialog)
        end_entry.grid(row=3, column=1, padx=5, pady=2)
        
        ttk.Label(dialog, text="步长:").grid(row=4, column=0, sticky="w", padx=5)
        step_entry = ttk.Entry(dialog)
        step_entry.grid(row=4, column=1, padx=5, pady=2)
        
        def apply_variables():
            """应用变量设置到URL"""
            var_name = var_name_entry.get()
            start = start_entry.get()
            end = end_entry.get()
            step = step_entry.get()
            
            if var_name and start and end and step:
                try:
                    self.url_var_config = {
                        'var_name': var_name,
                        'start': int(start),
                        'end': int(end),
                        'step': int(step)
                    }
                    current_url = self.url_entry.get()
                    if "{" not in current_url:
                        self.url_entry.insert(tk.END, f"/{{{var_name}}}")
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("错误", "请输入有效的数字")
        
        ttk.Button(dialog, text="应用", command=apply_variables).grid(row=5, column=0, columnspan=2, pady=10)

    def validate_input(self):
        """验证输入参数有效性"""
        if not self.url_entry.get():
            messagebox.showerror("错误", "请输入目标网址")
            return False
        if not self.xpath_entry.get():
            messagebox.showerror("错误", "请输入XPath表达式")
            return False
        return True

    def start_crawling(self):
        """开始爬取线程"""
        if not self.validate_input():
            return
            
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="爬取进行中...")
        
        # 创建并启动爬取线程
        threading.Thread(target=self.crawl_worker, daemon=True).start()

    def stop_crawling(self):
        """停止爬取"""
        self.running = False
        self.status_label.config(text="爬取已停止")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def crawl_worker(self):
        """爬取工作线程"""
        try:
            try:
                # 准备请求参数
                headers = {
                    'User-Agent': self.user_agent_entry.get(),
                    'X-Requested-With': self.x_requested_with_entry.get(),
                    'Content-Type': self.content_type_entry.get(),
                    'Accept-Language': self.accept_lang_entry.get(),
                    'Cookie': self.cookie_entry.get("1.0", tk.END).strip()
                }
                
                # 添加自定义请求头
                custom_headers = self.custom_headers_entry.get("1.0", tk.END).strip().split('\n')
                for header in custom_headers:
                    if ':' in header:
                        key, value = header.split(':', 1)
                        headers[key.strip()] = value.strip()

                # 执行爬取循环
                loop_count = int(self.loop_count.get())
                for i in range(loop_count):
                    if not self.running:
                        break
                    
                    # 随机延迟
                    delay = random.randint(0, self.current_delay.get())
                    time.sleep(delay)
                    
                    # 处理变量替换
                    current_url = self.url_entry.get()
                    if self.url_var_config:
                        var_name = self.url_var_config['var_name']
                        start = self.url_var_config['start']
                        step = self.url_var_config['step']
                        current_value = start + i * step
                        current_url = current_url.replace(f"{{{var_name}}}", str(current_value))
                    
                    # 发送请求
                    response = requests.get(
                        current_url,
                        headers=headers,
                        verify=self.ssl_verify.get(),
                        cert=(self.client_cert_entry.get(), self.client_key_entry.get()) if self.client_cert_entry.get() else None
                    )
                    response.encoding = 'utf-8'  # 显式设置编码
                    
                    # 解析内容
                    html = etree.HTML(response.text)
                    results = html.xpath(self.xpath_entry.get())
                    
                    # 更新界面
                    self.master.after(0, self.update_results, results)
                    
            except Exception as e:
                raise  # 将异常传递到外层处理

        except Exception as e:
            self.master.after(0, lambda e=e: messagebox.showerror("错误", f"爬取失败: {str(e)}"))
        finally:
            self.master.after(0, self.stop_crawling)

    def update_results(self, results):
        """更新结果展示"""
        current_count = len(self.tree.get_children()) // max(len(results), 1) + 1
        for idx, result in enumerate(results):
            self.tree.insert("", tk.END, values=(f"第{current_count}次爬取-结果 {idx+1}: {result.strip()}",))
            
    def save_results(self):
        """保存爬取结果"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("JSON 文件", "*.json")]
        )
        if not filepath:
            return
            
        try:
            if filepath.endswith('.csv'):
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["内容"])
                    for item in self.tree.get_children():
                        writer.writerow([self.tree.item(item)['values'][0]])
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    data = [self.tree.item(item)['values'][0] for item in self.tree.get_children()]
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    
            messagebox.showinfo("成功", "结果保存成功")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")

    def load_settings(self):
        """加载保存的配置"""
        try:
            if os.path.exists('crawler_settings.json'):
                with open('crawler_settings.json', 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    
                # 基本设置
                self.url_entry.insert(0, settings.get('url', ''))
                self.xpath_entry.insert(0, settings.get('xpath', ''))
                self.loop_count.set(settings.get('loop_count', 1))
                self.current_delay.set(settings.get('delay', 3))
                
                # 请求头设置
                self.user_agent_entry.delete(0, tk.END)
                self.user_agent_entry.insert(0, settings.get('user_agent', ''))
                self.x_requested_with_entry.delete(0, tk.END)
                self.x_requested_with_entry.insert(0, settings.get('x_requested_with', ''))
                self.content_type_entry.delete(0, tk.END)
                self.content_type_entry.insert(0, settings.get('content_type', ''))
                self.accept_lang_entry.delete(0, tk.END)
                self.accept_lang_entry.insert(0, settings.get('accept_language', ''))
                self.cookie_entry.delete("1.0", tk.END)
                self.cookie_entry.insert("1.0", settings.get('cookie', ''))
                
                # HTTPS设置
                self.ssl_verify.set(settings.get('ssl_verify', True))
                self.client_cert_entry.delete(0, tk.END)
                self.client_cert_entry.insert(0, settings.get('client_cert', ''))
                self.client_key_entry.delete(0, tk.END)
                self.client_key_entry.insert(0, settings.get('client_key', ''))
                
        except Exception as e:
            print(f"加载配置时出错: {str(e)}")

    def clear_results(self):
        """清空结果展示"""
        self.tree.delete(*self.tree.get_children())
        self.status_label.config(text="结果已清空")
        self.master.update()

    def save_settings(self):
        """保存当前配置"""
        settings = {
            'url': self.url_entry.get(),
            'xpath': self.xpath_entry.get(),
            'loop_count': self.loop_count.get(),
            'delay': self.current_delay.get(),
            'user_agent': self.user_agent_entry.get(),
            'x_requested_with': self.x_requested_with_entry.get(),
            'content_type': self.content_type_entry.get(),
            'accept_language': self.accept_lang_entry.get(),
            'cookie': self.cookie_entry.get("1.0", tk.END).strip(),
            'ssl_verify': self.ssl_verify.get(),
            'client_cert': self.client_cert_entry.get(),
            'client_key': self.client_key_entry.get()
        }
        
        try:
            with open('crawler_settings.json', 'w', encoding='utf-8') as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存配置时出错: {str(e)}")

    def on_closing(self):
        """关闭窗口事件处理"""
        if messagebox.askokcancel("退出", "确定要退出程序吗？"):
            self.save_settings()  # 关闭前保存配置
            self.running = False
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = WebCrawlerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
