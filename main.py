import tkinter as tk
from tkinter import simpledialog, messagebox
import random
import hashlib

usersAndPasswords = {}
usersAndSalt = {}
hashMethod = {}

def validUserID(user):
    for users in usersAndPasswords:
        if user == users:
            messagebox.showerror("Error", "User already exists.")
            return False
    return len(user) < 10

def validPassword(password):
    numCount = sum(1 for char in password if char.isdigit())
    return len(password) > 8 and numCount >= 2

def simpleHash(password, salt, display_frame):
    combined = password + salt
    hash_value = hashlib.sha256(combined.encode()).hexdigest()
    display_frame.update_hashing_process(f"Simple Hash: {hash_value}")
    return hash_value

def simpleHashWithPepper(password, salt, display_frame):
    pepper = "NetworksAndSecurityIsFun!"
    combined = password + salt + pepper
    hash_value = hashlib.sha256(combined.encode()).hexdigest()
    display_frame.update_hashing_process(f"Simple Hash with Pepper: {hash_value}")
    return hash_value

def repeatedHash(password, salt, iterations, display_frame):
    combined = password + salt
    for i in range(iterations):
        combined = hashlib.sha256(combined.encode()).hexdigest()
        display_frame.update_hashing_process(f"Iteration {i+1}: {combined}")
    return combined

def xorHash(password, salt, display_frame):
    combined = password + salt
    hashValue = 0
    for char in combined:
        hashValue ^= ord(char)
        hashValue = (hashValue * 31) & 0xFFFFFFFF
    hash_value = format(hashValue, 'x')
    display_frame.update_hashing_process(f"XOR Hash: {hash_value}")
    return hash_value

def rotateHash(password, salt, display_frame):
    combined = password + salt
    hashValue = 0
    for char in combined:
        hashValue = ((hashValue << 5) | (hashValue >> 27)) & 0xFFFFFFFF
        hashValue ^= ord(char)
    hash_value = format(hashValue, 'x')
    display_frame.update_hashing_process(f"Rotate Hash: {hash_value}")
    return hash_value

def crazyHash(password, salt, display_frame):
    combined = password + salt
    hash_value = 0
    for i, char in enumerate(combined):
        hash_value += (ord(char) * (i + 1)) ** 2
        hash_value ^= (hash_value << 7) & 0xFFFFFFFF
        hash_value ^= (hash_value >> 11) & 0xFFFFFFFF
        hash_value ^= (hash_value << 3) & 0xFFFFFFFF
        hash_value = (hash_value * 13 + ord(char)) & 0xFFFFFFFF
        hash_value ^= (hash_value << 17) & 0xFFFFFFFF
        hash_value ^= (hash_value >> 19) & 0xFFFFFFFF
        hash_value ^= (hash_value << 5) & 0xFFFFFFFF
    hash_value = format(hash_value, 'x')
    display_frame.update_hashing_process(f"Crazy Hash: {hash_value}")
    return hash_value

def AIHash(password, salt, display_frame):
    combined = password + salt
    hash_value = 0xC0FFEE  # Start with a caffeinated constant
    for i, char in enumerate(combined):
        # Absurd transformations
        hash_value ^= ((ord(char) * (i + 123)) ** 4) & 0xFFFFFFFF
        hash_value = ((hash_value << 3) | (hash_value >> 29)) & 0xFFFFFFFF
        hash_value ^= (hash_value * 0xBADC0DE ^ (ord(char) * 42)) & 0xFFFFFFFF
        hash_value += ((hash_value >> 11) | (hash_value << 21)) & 0xFFFFFFFF
        hash_value = (hash_value * 0xDEADBEEF + ~ord(char)) & 0xFFFFFFFF
        hash_value ^= ((hash_value << 7) + (hash_value >> 17)) & 0xFFFFFFFF
        # Throw in some prime magic
        hash_value ^= ((hash_value * 31 * ord(char) + 0x1337BEEF) % 0xFFFFFFFF)
        hash_value = (hash_value ^ 0xBAADF00D) & 0xFFFFFFFF
        hash_value ^= (((hash_value + i) * 0xCAFE) ^ ord(char) ** 3) & 0xFFFFFFFF

        # Bonus round: chaotic lookup table nonsense
        table = [0xDEAD, 0xBEEF, 0xC0DE, 0xC0FFEE, 0xBADF00D, 0xFEED]
        lookup = table[i % len(table)]
        hash_value ^= lookup

    # Final scramble
    hash_value ^= ((hash_value << 13) | (hash_value >> 19)) & 0xFFFFFFFF
    hash_value = (hash_value * 0xFACEFEED + 0xBABEFACE) & 0xFFFFFFFF
    hash_value = ~hash_value & 0xFFFFFFFF  # Bitwise inversion for the final touch

    # Extra nonsense: Convert to base 36 for added "readability"
    final_hash = format(hash_value, 'x') + '-' + format(hash_value, 'o') + '-' + format(hash_value, 'b')
    display_frame.update_hashing_process(f"AI Hash: {final_hash}")
    return final_hash

def hashPassword(password, salt, method, display_frame):
    if method == "Simple":
        return simpleHash(password, salt, display_frame)
    elif method == "Pepper":
        return simpleHashWithPepper(password, salt, display_frame)
    elif method == "Iterated":
        iterations = int(simpledialog.askstring("Input", "Enter number of iterations:"))
        if iterations > 1 and iterations < 5000:
            return repeatedHash(password, salt, iterations, display_frame)
        else:
            messagebox.showerror("Error", "Invalid number of iterations.")
            return hashPassword(password, salt, method, display_frame)
    elif method == "XOR":
        return xorHash(password, salt, display_frame)
    elif method == "Rotate":
        return rotateHash(password, salt, display_frame)
    elif method == "Crazy":
        return crazyHash(password, salt, display_frame)
    elif method == "AI":
        return AIHash(password, salt, display_frame)
    else:
        raise ValueError("Invalid hashing method")

def chooseHashMethod():
    methods = ["Simple", "Pepper", "Iterated", "XOR", "Rotate", "Crazy", "AI"]
    choice = simpledialog.askstring("Input", "Choose Your Hash Method:\n1. Simple Hash\n2. Hash with Pepper\n3. Iterated Hash\n4. XOR Hash\n5. Rotate Hash\n6. Crazy Hash\n7. AI Hash\n")
    if choice in map(str, range(1, 8)):
        return methods[int(choice) - 1]
    else:
        messagebox.showerror("Error", "Invalid choice.")
        return chooseHashMethod()

def addUser(frame, main_frame, display_frame):
    user = simpledialog.askstring("Input", "Create user name:", parent=frame)
    if not validUserID(user):
        return

    messagebox.showinfo("Info", "Password Requirements:\n* Longer than 8 characters\n* Must contain at least 2 numbers", parent=frame)
    pw = simpledialog.askstring("Input", f"Create the password for {user}:", show='*', parent=frame)
    while not validPassword(pw):
        messagebox.showerror("Error", "Invalid password choice.", parent=frame)
        pw = simpledialog.askstring("Input", f"Create the password for {user}:", show='*', parent=frame)

    salt = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
    method = chooseHashMethod()
    hashed_pw = hashPassword(pw, salt, method, display_frame)

    usersAndPasswords[user] = hashed_pw
    usersAndSalt[user] = salt
    hashMethod[user] = method
    messagebox.showinfo("Success", f"User '{user}' added successfully.", parent=frame)
    switch_frame(main_frame)

def verifyPassword(frame, main_frame, display_frame):
    user = simpledialog.askstring("Input", "Enter user:", parent=frame)
    password = simpledialog.askstring("Input", "Enter password:", show='*', parent=frame)
    if user in usersAndPasswords:
        salt = usersAndSalt[user]
        method = hashMethod[user]
        hashed_password = hashPassword(password, salt, method, display_frame)
        if usersAndPasswords[user] == hashed_password:
            messagebox.showinfo("Success", f"Password is correct, hello {user}", parent=frame)
        else:
            messagebox.showerror("Error", "Incorrect password.", parent=frame)
    else:
        messagebox.showerror("Error", "User not found.", parent=frame)
    switch_frame(main_frame)

def switch_frame(frame):
    frame.tkraise()

class DisplayFrame(tk.Frame):
    def __init__(self, parent, main_frame):
        super().__init__(parent)
        self.main_frame = main_frame
        self.text = tk.Text(self, wrap='word', height=20, width=50)
        self.text.pack(pady=10)
        tk.Button(self, text="Back", command=self.go_back).pack(pady=10)

    def update_hashing_process(self, message):
        self.text.insert(tk.END, message + "\n")
        self.text.see(tk.END)
        self.update_idletasks()

    def go_back(self):
        switch_frame(self.main_frame)

def main():
    root = tk.Tk()
    root.title("User Management System")

    main_frame = tk.Frame(root)
    add_user_frame = tk.Frame(root)
    login_frame = tk.Frame(root)
    display_frame = DisplayFrame(root, main_frame)

    for frame in (main_frame, add_user_frame, login_frame, display_frame):
        frame.grid(row=0, column=0, sticky='nsew')

    tk.Button(main_frame, text="Add User", command=lambda: switch_frame(add_user_frame)).pack(pady=10)
    tk.Button(main_frame, text="Log In", command=lambda: switch_frame(login_frame)).pack(pady=10)
    tk.Button(main_frame, text="Show Hashing Process", command=lambda: switch_frame(display_frame)).pack(pady=10)
    tk.Button(main_frame, text="Exit", command=root.quit).pack(pady=10)

    tk.Label(add_user_frame, text="Add User").pack(pady=10)
    tk.Button(add_user_frame, text="Proceed", command=lambda: addUser(add_user_frame, main_frame, display_frame)).pack(pady=10)
    tk.Button(add_user_frame, text="Back", command=lambda: switch_frame(main_frame)).pack(pady=10)

    tk.Label(login_frame, text="Log In").pack(pady=10)
    tk.Button(login_frame, text="Proceed", command=lambda: verifyPassword(login_frame, main_frame, display_frame)).pack(pady=10)
    tk.Button(login_frame, text="Back", command=lambda: switch_frame(main_frame)).pack(pady=10)

    switch_frame(main_frame)
    root.mainloop()

if __name__ == '__main__':
    main()