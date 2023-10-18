import wave
import matplotlib.pyplot as plt
#from scipy.io.wavfile import read

for i in range(4):
    file = 'example'+str(i+1)+'.wav'
    w = wave.open(file, 'r')
    print(w.getnframes())
"""
input_data = read("example1.wav")
audio = input_data[1]
plt.plot(audio[0:1024])
plt.ylabel("Amplitude")
plt.xlabel("Time")
plt.show()
"""

for i in range(10000):
    frame = w.readframes(i)
    print(frame)

print(w.getnframes())


"""
from scipy.io.wavfile import read
import matplotlib.pyplot as plt
plt.rcParams["figure.figsize"] = [7.50, 3.50]
plt.rcParams["figure.autolayout"] = True
input_data = read("my_audio.wav")
audio = input_data[1]
plt.plot(audio[0:1024])
plt.ylabel("Amplitude")
plt.xlabel("Time")
plt.show()
"""