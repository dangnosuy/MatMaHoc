from hashlib import sha256

key = input("Input key: ")
message = input("Input message: ")

input_ = key + message

print(sha256(input_.encode('utf-8')).hexdigest())