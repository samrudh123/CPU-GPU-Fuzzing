import io
import sys
import atheris
import zipfile
from tokenize import TokenError

with atheris.instrument_imports():
    import numpy as np
    
def TestOneInput(data):
    try:
        arr = np.load(io.BytesIO(data), allow_pickle=False)
        if arr is not None:
            _ = arr.shape
    except (ValueError, EOFError, TokenError, OSError, TypeError, MemoryError, UnicodeDecodeError, ZeroDivisionError, SyntaxError, OverflowError, zipfile.BadZipFile,
             zipfile.LargeZipFile, SystemError, AttributeError):
        pass
    
def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    
if __name__ == "__main__":
    main()