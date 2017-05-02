import matplotlib.pyplot as plt
import sys
from scipy.signal import butter, lfilter, freqz, medfilt

def filter(data):
  return data
  return medfilt(data, kernel_size=3)
  b, a = butter(0, 0.0001, 'low', analog=False)
  return lfilter(b, a, data)

def check(l):
  ca = 0
  cb = 0
  for a,b in zip(l[0], l[1]):
    if a>b:
      ca +=1
    else:
      cb += 1
  print("ca", ca)
  print("cb", cb)

if __name__ == "__main__":
  a = []
  with open(sys.argv[1]) as f:
    for line in f:
      lbl, *rest = line.strip().split(',')
      a.append(rest);
      plt.plot(filter(list(map(int, rest))), label=lbl)
  check(a);
  plt.legend()
  plt.show()


