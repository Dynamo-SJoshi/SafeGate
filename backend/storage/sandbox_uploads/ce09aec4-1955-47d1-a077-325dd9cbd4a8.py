import numpy as np
a = np.array([[1.9,2.8,3.4,4.7],[1.2,3.4,6.4,5.6],[1.5,2.6,3.7,4.8]])
b=np.zeros(5)
c=np.array([[640,640,640],[640,640,640],[640,640,640]],dtype=np.int32)

print(np.repeat(a,2))
