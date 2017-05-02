import matplotlib.pyplot as plt
import sys
from scipy.signal import butter, lfilter, freqz

def filter(data):
  b, a = butter(3, 0.1, 'low', analog=False)
  return lfilter(b, a, data)

if __name__ == "__main__":
  with open(sys.argv[1]) as f:
    for line in f:
      lbl, *rest = line.strip().split(',')
      plt.plot(filter(list(map(int, rest))), label=lbl)
  plt.legend()
  plt.show()
