from pypbc import *
import random
import time
import matplotlib.pyplot as plt

############################
# 协议所需函数
############################
def setup():
    """
    生成配对环境 pairing，并随机生成群生成元 g、h。
    返回：pairing, g, h
    """
    param_str = '''type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
'''
    params = Parameters(param_str)
    pairing = Pairing(params)
    g = Element.random(pairing, G1)
    h = Element.random(pairing, G1)
    return pairing, g, h

def commit(g, h, sigma, r):
    """
    C = g^sigma * h^r
    """
    return (g ** sigma) * (h ** r)

###########################
# Prover & Verifier (表3.1)
###########################
class Prover:
    def __init__(self, pairing, g, h, Phi, sigma, r):
        """
        pairing, g, h, 公共信息
        Phi: 集合
        sigma, r: 满足C = g^sigma * h^r
        """
        self.pairing = pairing
        self.g = g
        self.h = h
        self.Phi = Phi
        self.sigma = sigma
        self.r = r

    def pick_v_and_sendV(self, A_dict):
        """
        步骤2: Prover选v => V = A_sigma^v
        """
        self.v = Element.random(self.pairing, Zr)
        A_sigma = A_dict[self.sigma]
        V = A_sigma ** self.v
        return V

    def step2_send_aD(self, V, y):
        """
        步骤3:
          1) 选 s, t, m
          2) a = e(V,g)^(-s)* e(g,g)^t
             D = g^s * h^m
        """
        self.s = Element.random(self.pairing, Zr)
        self.t = Element.random(self.pairing, Zr)
        self.m = Element.random(self.pairing, Zr)

        # a
        eg_Vg = self.pairing.apply(V, self.g)  # e(V, g)
        eg_gg = self.pairing.apply(self.g, self.g)
        a = (eg_Vg ** (-self.s)) * (eg_gg ** self.t)

        # D
        D = (self.g ** self.s) * (self.h ** self.m)
        return a, D

    def step5_send_z(self, c):
        """
        步骤5:
          z_sigma= s - sigma*c, z_v= t - v*c, z_r= m - r*c
        """
        z_sigma = self.s - (self.sigma * c)
        z_v     = self.t - (self.v * c)
        z_r     = self.m - (self.r * c)
        return z_sigma, z_v, z_r

class Verifier:
    def __init__(self, pairing, g, h, Phi, C):
        """
        pairing, g, h, Phi, C= g^sigma h^r
        """
        self.pairing = pairing
        self.g = g
        self.h = h
        self.Phi = Phi
        self.C = C

    def pick_x_and_send_yAi(self):
        """
        步骤1:
        1) x in Zp
        2) y = g^x
        3) A_i= g^(1/(x+i))   对i in Phi
        返回 (x, y, A_dict)
        """
        self.x = random.randint(1, self.pairing.order())
        y = self.g ** self.x
        A_dict = {}
        for i in self.Phi:
            Ai = self.g ** (~Element(self.pairing, Zr, str(self.x + i)))
            A_dict[i] = Ai
        return self.x, y, A_dict

    def challenge_c(self):
        """ 步骤4: 随机挑战 c """
        c = Element.random(self.pairing, Zr)
        return c

    def verify_step6(self, V, y, a, D, c, z_sigma, z_v, z_r):
        """
        步骤6:
          D ?= C^c * h^z_r * g^z_sigma
          a ?= e(V,y)^c * e(V,g)^(-z_sigma)* e(g,g)^z_v
        """
        # 检查D
        left_D  = D
        right_D = (self.C ** c) * (self.h ** z_r) * (self.g ** z_sigma)
        if left_D != right_D:
            return False

        # 检查a
        left_a = a
        eVy = self.pairing.apply(V, y)
        eVg = self.pairing.apply(V, self.g)
        egg = self.pairing.apply(self.g, self.g)
        right_a = (eVy ** c) * (eVg ** (-z_sigma)) * (egg ** z_v)
        return left_a == right_a

########################################
# 计时 & 测试逻辑
########################################

def time_protocol_generation(Phi, sigma):
    """
    完整地执行表3.1中的六个步骤，并记录每一步的耗时
    返回: {
      "commit_time",   # 步骤C= g^sigma h^r
      "pickV_time",    # 步骤2: pick v => V
      "step2_time",    # 步骤3: Prover 选 s,t,m => a,D
      "challenge_time",# 步骤4: Verifier 随机 c
      "step5_time",    # 步骤5: Prover 发送 z_sigma,z_v,z_r
      "verify_time"    # 步骤6: Verifier检查
    }
    """
    pairing, g, h = setup()

    r = Element.random(pairing, Zr)
    # Step C= g^sigma h^r
    start = time.time()
    C = commit(g, h, sigma, r)
    commit_time = (time.time() - start)*1000

    # 构造Prover & Verifier
    prover = Prover(pairing, g, h, Phi, sigma, r)
    verif  = Verifier(pairing, g, h, Phi, C)

    # 步骤1: Verifier pick x => y, {A_i}
    start = time.time()
    x,y, A_dict = verif.pick_x_and_send_yAi()
    sign_time = (time.time() - start)*1000

    # 步骤2: pick v => V
    start = time.time()
    V = prover.pick_v_and_sendV(A_dict)
    pickV_time = (time.time() - start)*1000

    # 步骤3: step2_send_aD
    start = time.time()
    a, D = prover.step2_send_aD(V, y)
    step2_time = (time.time() - start)*1000

    # 步骤4: challenge
    start = time.time()
    c = verif.challenge_c()
    challenge_time = (time.time() - start)*1000

    # 步骤5: Prover => z_sigma,z_v,z_r
    start = time.time()
    z_sigma, z_v, z_r = prover.step5_send_z(c)
    step5_time = (time.time() - start)*1000

    # 步骤6: verify
    start = time.time()
    valid = verif.verify_step6(V, y, a, D, c, z_sigma, z_v, z_r)
    verify_time = (time.time() - start)*1000

    return {
        "sign_time": sign_time, 
        "commit_time": commit_time,
        "pickV_time": pickV_time,     
        "step2_time": step2_time,     # a, D
        "challenge_time": challenge_time,
        "step5_time": step5_time,     # response
        "verify_time": verify_time
    }

def plot_time_vs_set_size():
    """
    (1) 集合大小从10到100，每个大小重复10次，仅绘制“sign_time”折线图
        (相当于“Sign Time”).
    (2) 对固定集合大小=15，重复50次，输出其余 5 个数据平均值
    """
    # Part1: from 10 to 100, each repeated 10 times => average pickV_time
    set_sizes = range(10, 101, 1)
    REPEAT = 10
    Sign_list = []

    for size in set_sizes:
        sum_Sign = 0.0
        for _ in range(REPEAT):
            Phi = list(range(1, size+1))
            sigma = random.choice(Phi)
            data_ = time_protocol_generation(Phi, sigma)
            sum_Sign += data_["sign_time"]
        # 平均
        Sign_list.append(sum_Sign / REPEAT)

    import matplotlib.pyplot as plt
    plt.figure(figsize=(10,5))
    plt.plot(set_sizes, Sign_list, label="Sign Time")
    plt.xlabel("Set Size (Phi)")
    plt.ylabel("Time (ms)")
    plt.title("Sign Time vs Phi size")
    plt.legend()
    plt.grid(True)
    plt.show()

    # Part2: size=15, repeated=50 => commit, step2, challenge, step5, verify
    FIXED_SIZE = 15
    REPEAT2 = 50
    sum_commit=0.0
    sum_step2=0.0
    sum_chal=0.0
    sum_step5=0.0
    sum_verify=0.0

    for _ in range(REPEAT2):
        Phi = list(range(1, FIXED_SIZE+1))
        sigma = random.choice(Phi)
        data_ = time_protocol_generation(Phi, sigma)
        sum_commit += data_["commit_time"]
        sum_step2  += data_["step2_time"]
        sum_chal   += data_["challenge_time"]
        sum_step5  += data_["step5_time"]
        sum_verify += data_["verify_time"]

    avg_commit = sum_commit/REPEAT2
    avg_step2  = sum_step2 /REPEAT2
    avg_chal   = sum_chal /REPEAT2
    avg_step5  = sum_step5/REPEAT2
    avg_ver    = sum_verify/REPEAT2

    print(f"[Fixed Size={FIXED_SIZE}, repeated={REPEAT2} runs] Averages:")
    print(f"  Commit Time: {avg_commit:.3f} ms")
    print(f"  Step2 Time:  {avg_step2:.3f} ms")
    print(f"  Challenge:   {avg_chal:.3f} ms")
    print(f"  Step5 Time:  {avg_step5:.3f} ms")
    print(f"  Verify Time: {avg_ver:.3f} ms")


############
# 测试主流程
############
if __name__=="__main__":
    # 先做批量测试&绘图
    plot_time_vs_set_size()

    # 再演示一次完整执行
    Phi = [10,20,30,40,50]
    sigma = 20
    result_data = time_protocol_generation(Phi, sigma)
    print("[Single Run Data]", result_data)