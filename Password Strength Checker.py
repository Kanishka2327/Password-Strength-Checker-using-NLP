import tkinter as tk
from tkinter import messagebox
import random
import re
import hashlib
import string

# Global variable for OTP
otp = None

# Password history (hashed for security)
password_history = []

# Function to generate a strong password
def generate_strong_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    strong_password = ''.join(random.choices(characters, k=12))
    return strong_password

# Function to check password history
def check_password_history(password):
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    return hashed_pw in password_history

# Function to check password strength
def check_password_strength():
    password = entry.get()
    email = email_entry.get()

    if not email:
        feedback_label.config(text="Please enter your email for OTP verification.", fg="red")
        return

    if check_password_history(password):
        feedback_label.config(text="Password has been used before. Please choose a different one.", fg="red")
        return

    if (len(password) < 8 or not re.search(r"\d", password) or 
        not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or 
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        
        suggested_password = generate_strong_password()
        feedback_label.config(text=f"Weak password! Try this: {suggested_password}", fg="red")
        return

    feedback_label.config(text="Good job! Your password is strong.", fg="green")
    password_history.append(hashlib.sha256(password.encode()).hexdigest())
    send_otp_to_email(email)

# Function to send OTP via Email
def send_otp_to_email(email):
    global otp
    otp = ''.join(random.choices(string.digits, k=6))  # Generate 6-digit OTP
    messagebox.showinfo("OTP Generated", f"Your OTP is: {otp}")
    otp_entry.pack(pady=10)
    otp_label.pack(pady=5)
    verify_button.pack(pady=10)

# Function to verify OTP
def verify_otp():
    entered_otp = otp_entry.get()
    if entered_otp == otp:
        messagebox.showinfo("Success", "Password updated successfully!")
        otp_entry.pack_forget()
        otp_label.pack_forget()
        verify_button.pack_forget()
    else:
        messagebox.showerror("Error", "Invalid OTP. Please try again.")

# Toggle password visibility
def toggle_password_visibility():
    if entry.cget('show') == '*':
        entry.config(show='')
        toggle_button.config(text="Hide Password")
    else:
        entry.config(show='*')
        toggle_button.config(text="Show Password")

# Toggle Dark/Light Mode
def toggle_theme():
    if root.cget("bg") == "white":
        root.config(bg="#2c3e50")
        password_label.config(bg="#2c3e50", fg="white")
        email_label.config(bg="#2c3e50", fg="white")
        feedback_label.config(bg="#2c3e50", fg="white")
        otp_label.config(bg="#2c3e50", fg="white")
        toggle_theme_button.config(text="Light Mode", bg="#34495e", fg="white")
        check_button.config(bg="#27ae60", fg="white")
        verify_button.config(bg="#e74c3c", fg="white")
    else:
        root.config(bg="white")
        password_label.config(bg="white", fg="black")
        email_label.config(bg="white", fg="black")
        feedback_label.config(bg="white", fg="black")
        otp_label.config(bg="white", fg="black")
        toggle_theme_button.config(text="Dark Mode", bg="black", fg="white")
        check_button.config(bg="#3498db", fg="white")
        verify_button.config(bg="#e74c3c", fg="white")

# GUI Setup
root = tk.Tk()
root.title("Password Strength Checker with OTP")
root.geometry("400x550")
root.config(bg="white")  # Default theme is light

# Labels and Entries
password_label = tk.Label(root, text="Enter Password:", bg="white", font=("Arial", 12, "bold"))
password_label.pack(pady=10)

entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
entry.pack(pady=5)

email_label = tk.Label(root, text="Enter your Email for OTP:", bg="white", font=("Arial", 12, "bold"))
email_label.pack(pady=5)

email_entry = tk.Entry(root, width=30, font=("Arial", 12))
email_entry.pack(pady=5)

otp_label = tk.Label(root, text="Enter OTP sent to your Email:", bg="white", font=("Arial", 12, "bold"))
otp_entry = tk.Entry(root, width=30, font=("Arial", 12))
verify_button = tk.Button(root, text="Verify OTP", command=verify_otp, font=("Arial", 12), bg="#e74c3c", fg="white")

# Toggle buttons
toggle_button = tk.Button(root, text="Show Password", command=toggle_password_visibility, font=("Arial", 12), bg="#f39c12", fg="white")
toggle_button.pack(pady=5)

toggle_theme_button = tk.Button(root, text="Dark Mode", command=toggle_theme, font=("Arial", 12), bg="black", fg="white")
toggle_theme_button.pack(pady=5)

# Button to check password strength
check_button = tk.Button(root, text="Check Password Strength", command=check_password_strength, font=("Arial", 12), bg="#3498db", fg="white")
check_button.pack(pady=20)

# Feedback label
feedback_label = tk.Label(root, text="", font=('Helvetica', 10), bg="white")
feedback_label.pack(pady=10)

# Run the GUI
root.mainloop()
