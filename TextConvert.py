import tkinter as tk
from tkinter import messagebox

# Encoding/Decoding functions
def base64_encode(text):
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    binary_string = ''
    for char in text:
        binary_string += f"{ord(char):08b}"
    while len(binary_string) % 6 != 0:
        binary_string += '0'
    encoded_text = ''
    for i in range(0, len(binary_string), 6):
        encoded_text += base64_chars[int(binary_string[i:i+6], 2)]
    return encoded_text + '=' * ((4 - len(encoded_text) % 4) % 4)

def base64_decode(text):
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    binary_string = ''
    for char in text:
        if char not in base64_chars + "=":
            raise ValueError("Invalid Base64 encoding")
    if len(text) % 4 != 0:
        raise ValueError("Invalid Base64 encoding: Length must be a multiple of 4")
    for char in text:
        if char in base64_chars:
            binary_string += f"{base64_chars.index(char):06b}"
    decoded_text = ''
    for i in range(0, len(binary_string), 8):
        decoded_text += chr(int(binary_string[i:i+8], 2))
    return decoded_text

def base32_encode(text):
    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    binary_string = ''
    for char in text:
        binary_string += f"{ord(char):08b}"
    while len(binary_string) % 5 != 0:
        binary_string += '0'
    encoded_text = ''
    for i in range(0, len(binary_string), 5):
        encoded_text += base32_chars[int(binary_string[i:i+5], 2)]
    return encoded_text + '=' * ((8 - len(encoded_text) % 8) % 8)

def base32_decode(text):
    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    binary_string = ''
    for char in text:
        if char not in base32_chars + "=":
            raise ValueError("Invalid Base32 encoding")
    if len(text) % 8 != 0:
        raise ValueError("Invalid Base32 encoding: Length must be a multiple of 8")
    for char in text:
        if char in base32_chars:
            binary_string += f"{base32_chars.index(char):05b}"
    decoded_text = ''
    for i in range(0, len(binary_string), 8):
        decoded_text += chr(int(binary_string[i:i+8], 2))
    return decoded_text

def rot13(text):
    result = ''
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result

def rot47(text):
    result = ''
    for char in text:
        if 33 <= ord(char) <= 126:
            result += chr(33 + ((ord(char) - 33 + 47) % 94))
        else:
            result += char
    return result

def hex_encode(text):
    encoded_text = ''
    for char in text:
        encoded_text += f"{ord(char):02x}"
    return encoded_text

def hex_decode(text):
    decoded_text = ''
    for i in range(0, len(text), 2):
        decoded_text += chr(int(text[i:i+2], 16))
    return decoded_text

def base58_encode(text):
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in text:
        num = num * 256 + ord(char)
    encoded_text = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encoded_text = base58_chars[rem] + encoded_text
    for char in text:
        if char == '\x00':
            encoded_text = '1' + encoded_text
        else:
            break
    return encoded_text

def base58_decode(text):
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in text:
        if char not in base58_chars:
            raise ValueError("Invalid Base58 encoding")
        num = num * 58 + base58_chars.index(char)
    decoded_text = ''
    while num > 0:
        num, rem = divmod(num, 256)
        decoded_text = chr(rem) + decoded_text
    for char in text:
        if char == '1':
            decoded_text = '\x00' + decoded_text
        else:
            break
    return decoded_text

# Function to process the input text
def process_text():
    text = input_text.get().strip()
    method = encryption_method.get()
    action = encode_or_decode.get()

    if not text:
        messagebox.showerror("Error", "Input text cannot be empty!")
        return

    try:
        if method == "Base64":
            if action == "Encode":
                result = base64_encode(text)
            else:
                result = base64_decode(text)
        elif method == "Base58":
            if action == "Encode":
                result = base58_encode(text)
            else:
                result = base58_decode(text)
        elif method == "Base32":
            if action == "Encode":
                result = base32_encode(text)
            else:
                result = base32_decode(text)
        elif method == "ROT13":
            result = rot13(text)
        elif method == "ROT47":
            result = rot47(text)
        elif method == "Hexadecimal":
            if action == "Encode":
                result = hex_encode(text)
            else:
                result = hex_decode(text)

        output_text.set(result)

    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", "An unexpected error occurred.")

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")

# GUI setup
root = tk.Tk()
root.title("Simple Encoder/Decoder")
center_window(root, 450, 500)

title_font = ("Arial", 16, "bold")
label_font = ("Arial", 12, "bold")
button_font = ("Arial", 14)
entry_font = ("Arial", 12)

title = tk.Label(root, text="Text Converter", font=title_font, pady=10)
title.pack()

input_frame = tk.Frame(root, pady=10)
input_frame.pack(fill="x")
tk.Label(input_frame, text="Enter Text:", font=label_font).pack(side="left", padx=10)
input_text = tk.StringVar()
input_entry = tk.Entry(input_frame, textvariable=input_text, width=50, font=entry_font)  # Adjust width here
input_entry.pack(side="left", padx=10)

action_frame = tk.Frame(root, pady=10)
action_frame.pack(fill="x")
tk.Label(action_frame, text="Action:", font=label_font).pack(anchor="w", padx=10)
encode_or_decode = tk.StringVar(value="Encode")
tk.Radiobutton(action_frame, text="Encode", variable=encode_or_decode, value="Encode", font=button_font).pack(anchor="w", padx=20)
tk.Radiobutton(action_frame, text="Decode", variable=encode_or_decode, value="Decode", font=button_font).pack(anchor="w", padx=20)


method_frame = tk.Frame(root, pady=10)
method_frame.pack(fill="x")
tk.Label(method_frame, text="Method:", font=label_font).pack(anchor="w", padx=10)

encryption_method = tk.StringVar(value="Base64")
tk.Radiobutton(method_frame, text="Base64", variable=encryption_method, value="Base64", font=button_font).pack(anchor="w", padx=20)
tk.Radiobutton(method_frame, text="Base58", variable=encryption_method, value="Base58", font=button_font).pack(anchor="w", padx=20)
tk.Radiobutton(method_frame, text="Base32", variable=encryption_method, value="Base32", font=button_font).pack(anchor="w", padx=20)
tk.Radiobutton(method_frame, text="ROT13", variable=encryption_method, value="ROT13", font=button_font).pack(anchor="w", padx=20)
tk.Radiobutton(method_frame, text="ROT47", variable=encryption_method, value="ROT47", font=button_font).pack(anchor="w", padx=20)
tk.Radiobutton(method_frame, text="Hexadecimal", variable=encryption_method, value="Hexadecimal", font=button_font).pack(anchor="w", padx=20)

output_frame = tk.Frame(root, pady=10)
output_frame.pack(fill="x")
tk.Label(output_frame, text="Output:", font=label_font).pack(anchor="w", padx=10)
output_text = tk.StringVar()
output_entry = tk.Entry(output_frame, textvariable=output_text, font=entry_font, state="readonly", width=50)  # Adjust width here
output_entry.pack(anchor="w", padx=10, pady=5)

convert_button = tk.Button(root, text="Convert", font=button_font, command=process_text)
convert_button.pack(pady=20)

root.mainloop()
