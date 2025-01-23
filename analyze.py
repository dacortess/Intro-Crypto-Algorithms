import sys
import json
from collections import Counter

def calculate_coincidence_index(text: str) -> float:
    # Remove non-alphabetic characters and convert to uppercase
    text = ''.join(filter(str.isalpha, text.upper()))
    
    if len(text) <= 1:
        return 0.0
    
    # Count frequency of each letter
    freq = Counter(text)
    n = len(text)
    
    # Calculate Index of Coincidence
    sum_fi_2 = sum(count * (count - 1) for count in freq.values())
    ic = sum_fi_2 / (n * (n - 1))
    
    return ic

def main():
    # Get JSON data from command line argument
    json_str = sys.argv[1]
    data = json.loads(json_str)
    
    text = data['text']
    method = data['method']
    
    result = ""
    
    if method in ['multiplicative', 'permutation']:
        ic = calculate_coincidence_index(text)
        result = f"Index of Coincidence: {ic:.4f}"
    # Add other analysis methods as needed
    
    print(result)

if __name__ == "__main__":
    main()