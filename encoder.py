import binascii

text = "I owe you $3000."
hex_encoded = binascii.hexlify(text.encode()).decode()
print(text)
print(hex_encoded)

