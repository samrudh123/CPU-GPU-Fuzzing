import numpy as np, io
import re
import os

crashes = os.listdir(".")
crashes = [f for f in crashes if f.startswith("crash-")]

ooms = os.listdir(".")
ooms = [f for f in ooms if f.startswith("oom-")]

for crash in crashes:
    data = open(crash, "rb").read()
    try:
        np.load(io.BytesIO(data), allow_pickle=False)
    except Exception as e:
        print(type(e).__name__, ":", e)
        
for oom in ooms:
    data = open(oom, "rb").read()
    try:
        np.load(io.BytesIO(data), allow_pickle=False)
    except Exception as e:
        print(type(e).__name__, ":", e)