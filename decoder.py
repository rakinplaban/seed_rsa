import binascii

hex_encoded = "4160746f702073656372657421"  # Replace this with your actual hexadecimal string
decoded_text = binascii.unhexlify(hex_encoded).decode()
print(decoded_text)

