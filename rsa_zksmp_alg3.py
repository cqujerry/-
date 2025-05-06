import random
import time
import hashlib
from Crypto.Util.number import getPrime, inverse, GCD
import matplotlib.pyplot as plt

# RSA环境初始化
def rsa_setup(bits=1024):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    return p, q, n

# 哈希函数
def hash_sigma(sigma):
    return int(hashlib.sha256(str(sigma).encode()).hexdigest(), 16)

# 承诺函数
def commit(n, g, h, sigma, r):
    return (pow(g, sigma, n) * pow(h, r, n)) % n

# Prover类
class Prover:
    def __init__(self, n, g, h, S, sigma, r):
        self.n, self.g, self.h = n, g, h
        self.S, self.sigma, self.r = S, sigma, r

    def share_set_witness(self):
        u = random.randint(1, self.n - 1)
        s_list, e_list, w_list = [], [], []
        for s in self.S:
            while True:
                ui = random.getrandbits(128)
                ei = s * (2**128) + ui
                if GCD(ei, self.n) == 1:
                    wi = inverse(ei, (self.n - 1))
                    break
            s_list.append(s)
            e_list.append(ei)
            w_list.append(wi)
        v = pow(u, sum(e_list), self.n)
        return u, v, s_list, e_list, w_list

    def blinding(self):
        r_values = [random.randint(1, self.n**2) for _ in range(3)]
        return r_values

    def prove_of_knowledge(self, C):
        alpha = random.randint(1, self.n)
        beta = random.randint(1, self.n)
        gamma = random.randint(1, self.n)
        delta = random.randint(1, self.n)

        A = (pow(self.g, alpha, self.n) * pow(self.h, beta, self.n)) % self.n
        B = pow(self.g, gamma, self.n) * pow(self.h, delta, self.n) % self.n

        return A, B, (alpha, beta, gamma, delta)

# Verifier类
class Verifier:
    def __init__(self, n, g, h, C):
        self.n, self.g, self.h, self.C = n, g, h, C

    def verify_knowledge(self, A, B, params):
        alpha, beta, gamma, delta = params
        check1 = (pow(self.g, alpha, self.n) * pow(self.h, beta, self.n)) % self.n == A
        check2 = (pow(self.g, gamma, self.n) * pow(self.h, delta, self.n)) % self.n == B
        return check1 and check2

# 完整协议运行与计时


def run_protocol():
    p, q, n = rsa_setup()
    g, h = random.randint(1, n-1), random.randint(1, n-1)
    S = [random.randint(1, 1000) for _ in range(5)]
    sigma = random.choice(S)
    r = random.randint(1, n-1)

    start_time = time.time()
    C = commit(n, g, h, sigma, r)
    commit_time = (time.time() - start_time) * 1000

    prover = Prover(n, g, h, S, sigma, r)
    verifier = Verifier(n, g, h, C)

    start_time = time.time()
    u, v, s_list, e_list, w_list = prover.share_set_witness()
    share_time = (time.time() - start_time) * 1000

    start_time = time.time()
    r_values = prover.blinding()
    blinding_time = (time.time() - start_time) * 1000

    start_time = time.time()
    A, B, params = prover.prove_of_knowledge(C)
    prove_time = (time.time() - start_time) * 1000

    start_time = time.time()
    valid = verifier.verify_knowledge(A, B, params)
    verify_time = (time.time() - start_time) * 1000

    return {
        "commit_time": commit_time,
        "share_time": share_time,
        "blinding_time": blinding_time,
        "prove_time": prove_time,
        "verify_time": verify_time,
        "verification_result": valid
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
    Share_list = []

    for size in set_sizes:
        sum_Sign = 0.0
        for _ in range(REPEAT):
            Phi = list(range(1, size+1))
            sigma = random.choice(Phi)
            data_ = time_protocol_generation(Phi, sigma)
            sum_Share += data_["share_time"]
        # 平均
        Share_list.append(sum_Share / REPEAT)

    import matplotlib.pyplot as plt
    plt.figure(figsize=(10,5))
    plt.plot(set_sizes, Share_list)
    plt.title('Witness Generate Time vs Phi size')
    plt.xlabel('Set Size (Phi)')
    plt.ylabel('Time (ms)')
    plt.legend(['Witness Generate Time'])
    plt.grid(True)
    plt.show()

    # Part2: size=15, repeated=50 => commit_time, blinding_time, prove_time, verify_time
    FIXED_SIZE = 15
    REPEAT2 = 50
    sum_commit=0.0
    sum_blinding=0.0
    sum_prove=0.0
    sum_verify=0.0

    for _ in range(REPEAT2):
        Phi = list(range(1, FIXED_SIZE+1))
        sigma = random.choice(Phi)
        data_ = time_protocol_generation(Phi, sigma)
        sum_commit += data_["commit_time"]
        sum_blinding  += data_["blinding_time"]
        sum_prove += data_["prove_time"]
        sum_verify += data_["verify_time"]

    avg_commit = sum_commit/REPEAT2
    avg_blinding  = sum_blinding /REPEAT2
    avg_prove = sum_prove/REPEAT2
    avg_ver    = sum_verify/REPEAT2

    print(f"[Fixed Size={FIXED_SIZE}, repeated={REPEAT2} runs] Averages:")
    print(f"  Commit Time: {avg_commit:.3f} ms")
    print(f"  Blinding Time:  {avg_blinding:.3f} ms")
    print(f"  Prove Time:  {avg_prove:.3f} ms")
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
