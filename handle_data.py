from enum import Enum
import matplotlib.pyplot as plt
import numpy as np

TIME_SCALE = 1e-9 # To seconds

class Protocol(Enum):
    OTE_PRIM = "Primitive"
    OTE_IKNP = "IKNP"
    OTE_ALSZ = "ALSZ"

filenames = {
    Protocol.OTE_PRIM: "primitive",
    Protocol.OTE_IKNP: "IKNP_128_256",
    Protocol.OTE_ALSZ: "ALSZ_128_256",
}

def get_data(protocol: Protocol):
    with open(filenames[protocol]) as file:
        ms = list(map(int, file.readline().split(" ")))
        ks = list(map(int, file.readline().split(" ")))
        dic = {k: [] for k in ks}
        i = 0
        while line := file.readline():
            times = list(map(int, line.split(" ")))
            for k, time in zip(ks, times):
                dic[k].append((ms[i], time * TIME_SCALE))
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
    yticks = np.arange(0, max_y+1, 50.0)
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

def plot_128_256(protocol: Protocol):
    max_y = 0
    data, xticks = get_data(protocol)
    for k in data:
        xs = [x[0] for x in data[k]]
        ys = [x[1] for x in data[k]]
        max_y = max(max(ys), max_y)
        plt.plot(xs, ys, "o", label=f"$k={k}$")
    yticks = np.arange(0, max_y+1, 5.0)
    plot(f"Running time ({protocol.value})", "$m$", "Time [s]", xticks, yticks)

def main():
    plot_128_256(Protocol.OTE_ALSZ)

if __name__ == "__main__":
    main()