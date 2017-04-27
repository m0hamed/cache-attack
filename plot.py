import matplotlib.pyplot as plt

if __name__ == "__main__":
  with open(sys.argv[1]) as f:
    plt.hold(True)
    for line in f:
      plt.plot(map(int, line.split()))
