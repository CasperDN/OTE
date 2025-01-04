from enum import Enum
import matplotlib.pyplot as plt
import numpy as np

TIME_SCALE = 1e-9 # To seconds
PATH = "tests/"

class Protocol(Enum):
    OTE_PRIM = "Primitive"
    OTE_IKNP = "IKNP"
    OTE_ALSZ = "ALSZ"

filenames = {
    Protocol.OTE_PRIM: "Prim",
    Protocol.OTE_IKNP: "IKNP",
    Protocol.OTE_ALSZ: "ALSZ",
}

def normalize(xs, ys, f):
    res = [y/f(x) for x, y in zip(xs, ys)]
    return xs, res

def get_data(protocol: Protocol, filename=""):
    if not filename:
        filename = filenames[protocol]
    with open(PATH + filename) as file:
        ms = list(map(int, file.readline().split(" ")))
        ks = list(map(int, file.readline().split(" ")))
        dic = {k: [] for k in ks}
        i = 0
        while line := file.readline():
            times = list(map(int, line.split(" ")))
            for k, time in zip(ks, times):
                t = time * TIME_SCALE if time != -1 else np.nan
                dic[k].append((ms[i], t))
            i += 1
        return dic, ms

def plot(title, xlabel, ylabel, xticks, yticks):
    plt.xscale("log", base=2)
    plt.xticks(xticks)
    plt.yticks(yticks)
    plt.grid()
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.show() 

def plot_all():
    max_y = 0
    for proto in Protocol:
        data, xticks = get_data(proto)
        xs = [x[0] for x in data[128]]
        ys = [x[1] for x in data[128]]
        max_y = max(max(ys), max_y)
        plt.plot(xs, ys, "o", label=proto.value)
    yticks = np.arange(0, max_y+1, 100.0)
    plot("Running time ($k=128$)", "$m$", "Time [s]", xticks, yticks)

def plot_iknp_alsz():
    max_y = 0
    for proto in [Protocol.OTE_IKNP, Protocol.OTE_ALSZ]:
        data, xticks = get_data(proto)
        xs = [x[0] for x in data[256]]
        ys = [x[1] for x in data[256]]
        max_y = max(max(ys), max_y)
        plt.plot(xs, ys, "o", label=proto.value)
    yticks = np.arange(0, max_y+1, 10.0)
    plot("Running time ($k=256$)", "$m$", "Time [s]", xticks, yticks)

def plot_128_256(protocol: Protocol, f=lambda _: 1):
    max_y = 0
    data, xticks = get_data(protocol)
    for k in data:
        xs, ys = normalize([x[0] for x in data[k]],[x[1] for x in data[k]], f)
        max_y = max(max(ys), max_y)
        plt.plot(xs, ys, "o", label=f"$k={k}$")
    yticks = np.arange(0, max_y+1, 50.0)
    plot(f"Running time ({protocol.value})", "$m$", "Time [s]", xticks, yticks)

def avg():
    protocol = Protocol.OTE_ALSZ
    data, _ = get_data(protocol)
    sum_ys1 = sum([x[1] for x in data[128]])
    sum_ys2 = sum([x[1] for x in data[256]])

    avg_ys1 = sum_ys1 / len(data[128])
    avg_ys2 = sum_ys2 / len(data[256])
    print(avg_ys1, avg_ys2)
   

def main():
    # plot_all()
    plot_128_256(Protocol.OTE_IKNP, lambda x: 1)
    # avg()

if __name__ == "__main__":
    main()