# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import messagebox, scrolledtext
from pypbc import *
import random
import hashlib
import os

# 设置中文支持
os.environ['LC_ALL'] = 'zh_CN.UTF-8'
os.environ['LANG'] = 'zh_CN.UTF-8'

# ===============================
# 工具函数
# ===============================
def setup():
    param_str = '''type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1'''
    params = Parameters(param_str)
    pairing = Pairing(params)
    g = Element.random(pairing, G1)
    h = Element.random(pairing, G1)
    return pairing, g, h

def hash_sigma(sigma):
    return int(hashlib.sha256(str(sigma).encode()).hexdigest(), 16)

def commit(g, h, sigma, r_elem):
    hashed_sigma = hash_sigma(sigma)
    return (g ** hashed_sigma) * (h ** r_elem)

# ===============================
# Prover & Verifier
# ===============================
class Prover:
    def __init__(self, pairing, g, h, Phi, sigma, r):
        self.pairing, self.g, self.h = pairing, g, h
        self.Phi, self.sigma, self.r = Phi, sigma, r

    def pick_v_and_sendV(self, A_dict):
        self.v = Element.random(self.pairing, Zr)
        return A_dict[self.sigma] ** self.v

    def step2_send_aD(self, V, y):
        self.s, self.t, self.m = (Element.random(self.pairing, Zr) for _ in range(3))
        a = (self.pairing.apply(V, self.g) ** (-self.s)) * (self.pairing.apply(self.g, self.g) ** self.t)
        D = (self.g ** self.s) * (self.h ** self.m)
        return a, D

    def step5_send_z(self, c):
        hashed_sigma = hash_sigma(self.sigma)
        z_sigma = self.s - Element(self.pairing, Zr, str(hashed_sigma)) * c
        z_v = self.t - self.v * c
        z_r = self.m - self.r * c
        return z_sigma, z_v, z_r

class Verifier:
    def __init__(self, pairing, g, h, Phi, C):
        self.pairing, self.g, self.h, self.Phi, self.C = pairing, g, h, Phi, C

    def pick_x_and_send_yAi(self):
        self.x = random.randint(1, self.pairing.order())
        y = self.g ** self.x
        A_dict = {i: self.g ** (~Element(self.pairing, Zr, str(self.x + hash_sigma(i)))) for i in self.Phi}
        return self.x, y, A_dict

    def challenge_c(self):
        return Element.random(self.pairing, Zr)

    def verify_step6(self, V, y, a, D, c, z_sigma, z_v, z_r):
        left_a = a
        left_D = D
        right_D = (self.C ** c) * (self.h ** z_r) * (self.g ** z_sigma)
        if left_D != right_D:
            return False
        eVy = self.pairing.apply(V, y)
        eVg = self.pairing.apply(V, self.g)
        egg = self.pairing.apply(self.g, self.g)
        right_a = (eVy ** c) * (eVg ** (-z_sigma)) * (egg ** z_v)
        return left_a == right_a

# ===============================
# 简化调用函数
# ===============================
def generate_commitment(pairing, g, h, sigma):
    r_elem = Element.random(pairing, Zr)
    C_elem = commit(g, h, sigma, r_elem)
    return C_elem, r_elem

def simulate_proof(pairing, g, h, Phi, sigma, C_elem, r_elem):
    prover   = Prover(pairing, g, h, Phi, sigma, r_elem)
    verifier = Verifier(pairing, g, h, Phi, C_elem)

    _, y, A_dict = verifier.pick_x_and_send_yAi()
    V = prover.pick_v_and_sendV(A_dict)
    a, D = prover.step2_send_aD(V, y)
    c = verifier.challenge_c()
    z_sigma, z_v, z_r = prover.step5_send_z(c)

    return {
        'g': str(g),
        'h': str(h),
        'V': str(V), 'y': str(y), 'a': str(a), 'D': str(D),
        'c': str(c), 'z_sigma': str(z_sigma), 'z_v': str(z_v), 'z_r': str(z_r)
    }

def verify_proof(pairing, C_elem, proof):
    try:
        g_elem = Element(pairing, G1, proof['g'])
        h_elem = Element(pairing, G1, proof['h'])
        V = Element(pairing, G1, proof['V'])
        y = Element(pairing, G1, proof['y'])
        a = Element(pairing, GT, proof['a'])
        D = Element(pairing, G1, proof['D'])
        c = Element(pairing, Zr, proof['c'])
        z_sigma = Element(pairing, Zr, proof['z_sigma'])
        z_v = Element(pairing, Zr, proof['z_v'])
        z_r = Element(pairing, Zr, proof['z_r'])
    except Exception as e:
        print("解析proof失败:", e)
        return False

    verifier = Verifier(pairing, g_elem, h_elem, [], C_elem)
    return verifier.verify_step6(V, y, a, D, c, z_sigma, z_v, z_r)

# ===============================
# GUI界面
# ===============================

class ZKPSM_GUI:
    def __init__(self, root, pairing, g, h):
        self.root = root
        self.root.title("Zero Knowledge Set Membership Proof")
        self.root.geometry("700x650")
        self.pairing, self.g, self.h = pairing, g, h
        self.main_menu()
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def main_menu(self):
        self.clear_window()

        title = tk.Label(self.root, text="零知识集合成员证明系统", font=("微软雅黑", 16), pady=20)
        title.pack()

        btn_style = {'font': ("微软雅黑", 14), 'width': 20, 'pady': 10}

        tk.Button(self.root, text="承诺生成", command=self.commitment_page, bg="#4caf50", fg="white", **btn_style).pack(pady=10)
        tk.Button(self.root, text="证明生成", command=self.proof_generate_page, bg="#2196f3", fg="white", **btn_style).pack(pady=10)
        tk.Button(self.root, text="证明验证", command=self.proof_verify_page, bg="#ff5722", fg="white", **btn_style).pack(pady=10)
        tk.Button(self.root, text="退出", command=self.root.quit, bg="#f44336", fg="white", **btn_style).pack(pady=5)
        
    def add_scrollbar(self):
        canvas = tk.Canvas(self.root, borderwidth=0)
        frame = tk.Frame(canvas)
        vsb = tk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((4,4), window=frame, anchor="nw", tags="frame")

        frame.bind("<Configure>", lambda event, canvas=canvas: canvas.configure(scrollregion=canvas.bbox("all")))
        return frame
    
    def center_window(self, width, height):
        screen_w, screen_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (screen_w - width) // 2, (screen_h - height) // 2
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def commitment_page(self):
        self.clear_window()
        frame = self.add_scrollbar()

        tk.Label(frame, text="秘密值 sigma:", font=("微软雅黑", 12)).pack(pady=5)
        sigma_entry = tk.Entry(frame, width=60)
        sigma_entry.pack(pady=5)

        def generate_commitment_gui():
            sigma = sigma_entry.get()
            C_elem, r_elem = generate_commitment(self.pairing, self.g, self.h, sigma)
            result_text.config(state='normal')
            result_text.delete('1.0', tk.END)
            result_text.insert(tk.END, f"承诺C: {str(C_elem)}\n随机值r: {str(r_elem)}")
            result_text.config(state='disabled')

        tk.Button(frame, text="生成承诺", command=generate_commitment_gui, bg="#4caf50", fg="white", font=("微软雅黑", 12)).pack(pady=10)

        result_text = scrolledtext.ScrolledText(frame, width=80, height=10, font=("Consolas", 10))
        result_text.pack(pady=5)
        result_text.config(state='disabled')

        tk.Button(frame, text="返回", command=self.main_menu, font=("微软雅黑", 12)).pack(pady=10)

    def proof_generate_page(self):
        self.clear_window()
        frame = self.add_scrollbar()

        fields = ["集合元素（逗号分隔）:", "秘密值 sigma:", "承诺 C:", "随机值 r:"]
        entries = []
        for field in fields:
            tk.Label(frame, text=field, font=("微软雅黑", 12)).pack(pady=5)
            entry = tk.Entry(frame, width=60)
            entry.pack(pady=5)
            entries.append(entry)

        result_text = scrolledtext.ScrolledText(frame, width=80, height=10, font=("Consolas", 10))
        result_text.pack(pady=5)

        def simulate_proof_gui():
            Phi = [x.strip() for x in entries[0].get().split(',')]
            sigma, C_input, r_input = entries[1].get(), entries[2].get(), entries[3].get()

            try:
                C_elem = Element(self.pairing, G1, C_input)
                r_elem = Element(self.pairing, Zr, r_input)
            except Exception as e:
                messagebox.showerror("错误", f"输入格式错误: {e}")
                return

            if sigma not in Phi:
                sigma = random.choice(Phi)
                messagebox.showwarning("提示", f"sigma不在集合中，已随机选择'{sigma}'")

            proof = simulate_proof(self.pairing, self.g, self.h, Phi, sigma, C_elem, r_elem)
            result_text.delete('1.0', tk.END)
            result_text.insert(tk.END, str(proof))

        tk.Button(frame, text="生成模拟证明", command=simulate_proof_gui, bg="#2196f3", fg="white", font=("微软雅黑", 12)).pack(pady=10)
        tk.Button(frame, text="返回", command=self.main_menu, font=("微软雅黑", 12)).pack(pady=5)

    def proof_verify_page(self):
        self.clear_window()
        frame = self.add_scrollbar()

        tk.Label(frame, text="承诺 C:", font=("微软雅黑", 12)).pack(pady=5)
        C_entry = tk.Entry(frame, width=60)
        C_entry.pack(pady=5)

        tk.Label(frame, text="待验证证明字典:", font=("微软雅黑", 12)).pack(pady=5)
        proof_entry = scrolledtext.ScrolledText(frame, width=80, height=8, font=("Consolas", 10))
        proof_entry.pack(pady=5)

        def verify_proof_gui():
            C_input = C_entry.get()
            proof_input = proof_entry.get('1.0', tk.END)
            try:
                C_elem = Element(self.pairing, G1, C_input)
                proof_dict = eval(proof_input)
            except Exception as e:
                messagebox.showerror("error", f"输入格式错误: {e}")
                return

            result = verify_proof(self.pairing, C_elem, proof_dict)
            messagebox.showinfo("result", "验证通过 (accept)" if result else "验证失败 (reject)")

        tk.Button(frame, text="验证证明", command=verify_proof_gui, bg="#ff5722", fg="white", font=("微软雅黑", 12)).pack(pady=10)
        tk.Button(frame, text="返回", command=self.main_menu, font=("微软雅黑", 12)).pack(pady=5)

if __name__ == "__main__":
    pairing, g, h = setup()
    root = tk.Tk()
    gui = ZKPSM_GUI(root, pairing, g, h)
    root.mainloop()