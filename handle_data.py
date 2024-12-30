from enum import Enum
import matplotlib.pyplot as plt

TIME_SCALE = 1e-9 # To seconds

class Protocol(Enum):
    OTE_PRIMITIVE = "Primitive"
    OTE_IKNP = "IKNP"
    OTE_BETTER_NETWORK = "ALSZ"

filenames = {
    Protocol.OTE_PRIMITIVE: "primitive",
    Protocol.OTE_IKNP: "ote",
    Protocol.OTE_BETTER_NETWORK: "ote_net",
}

def get_data(protocol: Protocol):
    with open(filenames[protocol]) as file:
        ms = list(map(int, file.readline().split(" ")))
        ks = list(map(int, file.readline().split(" ")))
        times = {}
        for k in ks:
            l = []
            for m in ms:
                time = int(file.readline()) * TIME_SCALE
                l.append((m,time))
            times[k] = l
        return times, ms

def plot_all():
    for proto in [Protocol.OTE_IKNP]:
    # for proto in Protocol:
        data, ticks = get_data(proto)
        xs = [x[0] for x in data[128]]
        ys = [x[1] for x in data[128]]
        plt.plot(xs, ys, "o", label=proto.value)
    plt.xscale("log", base=2)
    plt.xticks(ticks)
    plt.grid()
    plt.title("All Protocols")
    plt.xlabel("m")
    plt.ylabel("Time [s]")
    plt.legend()
    plt.show() 

def main():
    plot_all()

if __name__ == "__main__":
    main()