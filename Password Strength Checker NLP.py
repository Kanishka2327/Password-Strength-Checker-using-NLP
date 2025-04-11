import tkinter as tk
from tkinter import messagebox
import sqlite3
import random
import re
import hashlib
import string
import webbrowser

def open_website():
    webbrowser.open("https://www.passwordmonster.com/")  # Replace with your desired URL

# Database setup
def setup_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

setup_database()

# Global variables
otp = None
password_history = []
dark_mode = False

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_history(password):
    return hash_password(password) in password_history

def generate_strong_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(characters, k=12))

def check_password_strength():
    password = password_entry.get()
    email = email_entry.get()

    if not email:
        feedback_label.config(text="Please enter your email for OTP verification.", fg="red")
        return

    if check_password_history(password):
        feedback_label.config(text="Password has been used before. Choose a different one.", fg="red")
        return

    if (len(password) < 8 or not re.search(r"\d", password) or
        not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        
        suggested_password = generate_strong_password()
        feedback_label.config(text=f"Weak password! Try this: {suggested_password}", fg="red")
        return

    feedback_label.config(text="Strong password!", fg="green")
    password_history.append(hash_password(password))
    send_otp_to_email(email)

def send_otp_to_email(email):
    global otp
    otp = ''.join(random.choices(string.digits, k=6))
    messagebox.showinfo("OTP Generated", f"Your OTP is: {otp}")
    otp_label.pack()
    otp_entry.pack()
    verify_button.pack()
    resend_otp_button.pack()

def resend_otp():
    email = email_entry.get()
    if email:
        send_otp_to_email(email)
    else:
        messagebox.showerror("Error", "Please enter your email to resend OTP.")


def verify_otp():
    global otp
    entered_otp = otp_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if entered_otp == otp:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hash_password(password)))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Registration successful!")
        open_website()  # Opens Password Monster after registration

        otp_label.pack_forget()
        otp_entry.pack_forget()
        verify_button.pack_forget()
        resend_otp_button.pack_forget()
    else:
        messagebox.showerror("Error", "Invalid OTP. Try again.")


def login():
    email = email_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()

    if result and result[0] == hash_password(password):
        messagebox.showinfo("Success", "Login successful!")
    else:
        feedback_label.config(text="Invalid credentials. Try again!", fg="red")

def toggle_dark_mode():
    global dark_mode
    dark_mode = not dark_mode
    bg_color = "#2C2F33" if dark_mode else "white"
    fg_color = "white" if dark_mode else "black"
    
    root.config(bg=bg_color)
    email_label.config(bg=bg_color, fg=fg_color)
    password_label.config(bg=bg_color, fg=fg_color)
    otp_label.config(bg=bg_color, fg=fg_color)
    feedback_label.config(bg=bg_color, fg=fg_color)
    dark_mode_button.config(text="Light Mode" if dark_mode else "Dark Mode")

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        show_password_button.config(text="Hide Password")
    else:
        password_entry.config(show='*')
        show_password_button.config(text="Show Password")

# GUI Setup
root = tk.Tk()
root.title("Login/Register")
root.geometry("400x600")
root.config(bg="white")

email_label = tk.Label(root, text="Enter Email:", bg="white")
email_label.pack(pady=5)

email_entry = tk.Entry(root, width=30)
email_entry.pack(pady=5)

password_label = tk.Label(root, text="Enter Password:", bg="white")
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)

show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility)
show_password_button.pack(pady=5)

otp_label = tk.Label(root, text="Enter OTP:", bg="white")
otp_entry = tk.Entry(root, width=30)
verify_button = tk.Button(root, text="Verify OTP", command=verify_otp)
resend_otp_button = tk.Button(root, text="Resend OTP", command=resend_otp)

register_button = tk.Button(root, text="Register", command=check_password_strength)
register_button.pack(pady=10)

login_button = tk.Button(root, text="Login", command=login)
login_button.pack(pady=10)

dark_mode_button = tk.Button(root, text="Dark Mode", command=toggle_dark_mode)
dark_mode_button.pack(pady=10)

feedback_label = tk.Label(root, text="", font=('Helvetica', 10), bg="white")
feedback_label.pack(pady=10)

root.mainloop()
