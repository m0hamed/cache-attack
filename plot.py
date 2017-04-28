import matplotlib.pyplot as plt
import sys

if __name__ == "__main__":
  with open(sys.argv[1]) as f:
    for line in f:
      label, *rest = line.strip().split(',')
      plt.plot(list(map(int, rest)))
  plt.show()
