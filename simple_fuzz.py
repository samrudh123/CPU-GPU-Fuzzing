import random
import string

def process_data(data: str) -> str:
    if not isinstance(data, str):
        return "Error: Input must be a string."
    
    # The hidden bug deep in the logic
    if len(data) >= 10:
        if data.startswith("!CR"):
            # Simulating a fatal program crash or vulnerability
            raise RuntimeError("FATAL SYSTEM FAULT: Malformed header processed!")
            
    return "Data processed safely."

def simple_fuzzer(max_iterations=100000):
    print(f"Starting fuzzing campaign ({max_iterations} max iterations)...")
    
    # Define the characters we want to throw at the program
    charset = string.ascii_letters + string.punctuation
    
    for i in range(max_iterations):
        # 1. Generate a random length for our payload
        length = random.randint(1, 100)
        
        # 2. Generate the random payload (the "fuzz")
        payload = ''.join(random.choice(charset) for _ in range(length))
        
        # 3. Feed the fuzz to the target and monitor for unhandled exceptions
        try:
            process_data(payload)
        except RuntimeError as e:
            # We caught a crash!
            print("\n💥 CRASH DETECTED!")
            print(f"Iteration: {i}")
            print(f"Payload:   {repr(payload)}")
            print(f"Error:     {e}")
            return # Stop fuzzing after finding the bug
            
    print("\nFuzzing complete. No crashes found.")

if __name__ == "__main__":
    simple_fuzzer()