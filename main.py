import tkinter as tk
from tkinter import messagebox
import json
import hashlib

class PasswordManager:
    def __init__(self):
        self.passwords = {}
        self.load_passwords()

    def load_passwords(self):
        try:
            with open("passwords.json", "r") as file:
                encrypted_data = file.read()
                decrypted_data = self.decrypt(encrypted_data)
                self.passwords = json.loads(decrypted_data)
        except FileNotFoundError:
            pass
        except json.JSONDecodeError:
            pass

    def save_passwords(self):
        with open("passwords.json", "w") as file:
            encrypted_data = self.encrypt(json.dumps(self.passwords))
            file.write(encrypted_data)

    def encrypt(self, data):
        # Simple encryption for demonstration purposes only
        return hashlib.sha256(data.encode()).hexdigest()

    def decrypt(self, data):
        # Simple decryption for demonstration purposes only
        return data

    def add_password(self, website, username, password):
        if website in self.passwords:
            messagebox.showinfo("Info", "Website already exists. Updating password.")
        self.passwords[website] = {"username": username, "password": password}
        self.save_passwords()
        messagebox.showinfo("Info", "Password added/updated successfully for " + website)

    def get_password(self, website):
        if website in self.passwords:
            return self.passwords[website]
        else:
            messagebox.showerror("Error", "Website not found in password manager.")

    def delete_password(self, website):
        if website in self.passwords:
            del self.passwords[website]
            self.save_passwords()
            messagebox.showinfo("Info", "Password deleted successfully for " + website)
        else:
            messagebox.showerror("Error", "Website not found in password manager.")

    def list_websites(self):
        websites = "\n".join(self.passwords.keys())
        messagebox.showinfo("List of Websites", "List of Websites in Password Manager:\n" + websites)


class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.password_manager = PasswordManager()

        self.website_label = tk.Label(master, text="Website:")
        self.website_label.grid(row=0, column=0, sticky="w")
        self.website_entry = tk.Entry(master)
        self.website_entry.grid(row=0, column=1)

        self.username_label = tk.Label(master, text="Username:")
        self.username_label.grid(row=1, column=0, sticky="w")
        self.username_entry = tk.Entry(master)
        self.username_entry.grid(row=1, column=1)

        self.password_label = tk.Label(master, text="Password:")
        self.password_label.grid(row=2, column=0, sticky="w")
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.grid(row=2, column=1)

        self.add_button = tk.Button(master, text="Add/Update", command=self.add_password)
        self.add_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.get_button = tk.Button(master, text="Get", command=self.get_password)
        self.get_button.grid(row=4, column=0, columnspan=2, pady=5)

        self.delete_button = tk.Button(master, text="Delete", command=self.delete_password)
        self.delete_button.grid(row=5, column=0, columnspan=2, pady=5)

        self.list_button = tk.Button(master, text="List Websites", command=self.list_websites)
        self.list_button.grid(row=6, column=0, columnspan=2, pady=5)

    def add_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.password_manager.add_password(website, username, password)

    def get_password(self):
        website = self.website_entry.get()
        password_info = self.password_manager.get_password(website)
        if password_info:
            messagebox.showinfo("Password Info", f"Username: {password_info['username']}\nPassword: {password_info['password']}")

    def delete_password(self):
        website = self.website_entry.get()
        self.password_manager.delete_password(website)

    def list_websites(self):
        self.password_manager.list_websites()


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
