import sys

def main():
    filename = sys.argv[1]

    with open(filename, 'rb') as file: # r:read, b:binary
        data = file.read()
    
    print(f"File size: {len(data)} bytes")

if __name__ == "__main__":
    main()