import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sqlite3
import random
import re
import hashlib
import string
import webbrowser
from datetime import datetime
import pyperclip  

# Database setup with additional tables
def setup_database():
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Password history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            password_hash TEXT,
            used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
    """)
    
    # Password vault table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_vault (
            vault_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            website TEXT,
            username TEXT,
            password TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
    """)
    
    conn.commit()
    conn.close()

setup_database()

# Global variables
current_user = None
dark_mode = False
password_visibility = False

# Security functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_strong_password(length=16):
    """Generate a cryptographically strong password"""
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(random.SystemRandom().choices(characters, k=length))
        if (len(password) >= 8 and re.search(r"\d", password) and
            re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
            return password

def check_password_strength(password):
    """Check password strength and return feedback"""
    if len(password) < 8:
        return "Very Weak (too short)", 0
    elif not re.search(r"\d", password):
        return "Weak (missing numbers)", 1
    elif not re.search(r"[A-Z]", password):
        return "Medium (missing uppercase)", 2
    elif not re.search(r"[a-z]", password):
        return "Medium (missing lowercase)", 2
    elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Strong (missing special chars)", 3
    elif len(password) >= 12:
        return "Very Strong", 4
    else:
        return "Strong", 3

def check_password_history(user_id, password):
    """Check if password has been used before"""
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT password_hash FROM password_history 
        WHERE user_id = ? AND password_hash = ?
    """, (user_id, hash_password(password)))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def send_otp_to_email(email):
    """Simulate sending OTP (in a real app, this would send an actual email)"""
    otp = ''.join(random.choices(string.digits, k=6))
    messagebox.showinfo("OTP Generated", f"Your OTP is: {otp}\n(In a real app, this would be sent to your email)")
    return otp

# User management functions
def register_user():
    email = email_entry.get().strip()
    password = password_entry.get()
    
    if not email or not password:
        update_feedback("Please enter both email and password", "red")
        return
    
    # Check password strength
    strength, score = check_password_strength(password)
    if score < 3:  # Require at least "Strong" password
        suggested = generate_strong_password()
        update_feedback(f"Password too weak ({strength}). Try: {suggested}", "red")
        return
    
    # Check if email already exists
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        update_feedback("Email already registered", "red")
        return
    
    # Generate OTP
    otp = send_otp_to_email(email)
    
    # Show OTP verification UI
    show_otp_verification(email, password, otp)

def show_otp_verification(email, password, otp):
    """Show OTP verification controls"""
    for widget in [otp_label, otp_entry, verify_button, resend_otp_button]:
        widget.pack(pady=5)
    
    def verify():
        if otp_entry.get() == otp:
            # Save user to database
            conn = sqlite3.connect("password_manager.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (email, password_hash) 
                VALUES (?, ?)
            """, (email, hash_password(password)))
            user_id = cursor.lastrowid
            
            # Add to password history
            cursor.execute("""
                INSERT INTO password_history (user_id, password_hash)
                VALUES (?, ?)
            """, (user_id, hash_password(password)))
            
            conn.commit()
            conn.close()
            
            # Hide OTP controls
            for widget in [otp_label, otp_entry, verify_button, resend_otp_button]:
                widget.pack_forget()
            
            update_feedback("Registration successful!", "green")
            show_main_application(user_id)
        else:
            update_feedback("Invalid OTP", "red")
    
    verify_button.config(command=verify)
    resend_otp_button.config(command=lambda: send_otp_to_email(email))

def login_user():
    email = email_entry.get().strip()
    password = password_entry.get()
    
    if not email or not password:
        update_feedback("Please enter both email and password", "red")
        return
    
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user_id, password_hash FROM users WHERE email = ?
    """, (email,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[1] == hash_password(password):
        update_feedback("Login successful!", "green")
        show_main_application(result[0])
    else:
        update_feedback("Invalid credentials", "red")

def show_main_application(user_id):
    """Show the main password manager interface"""
    global current_user
    current_user = user_id
    
    # Hide login controls
    for widget in login_frame.winfo_children():
        widget.pack_forget()
    
    # Show main application
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Load saved passwords
    refresh_vault()

def refresh_vault():
    """Refresh the password vault display"""
    vault_tree.delete(*vault_tree.get_children())
    
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT vault_id, website, username, password, notes 
        FROM password_vault WHERE user_id = ?
    """, (current_user,))
    
    for row in cursor.fetchall():
        vault_tree.insert("", tk.END, values=row[1:])  # Skip vault_id
    
    conn.close()

def add_to_vault():
    """Add a new password to the vault"""
    website = website_entry.get().strip()
    username = username_entry.get().strip()
    password = vault_password_entry.get()
    notes = notes_entry.get("1.0", tk.END).strip()
    
    if not website or not username or not password:
        messagebox.showerror("Error", "Website, username and password are required")
        return
    
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO password_vault (user_id, website, username, password, notes)
        VALUES (?, ?, ?, ?, ?)
    """, (current_user, website, username, password, notes))
    conn.commit()
    conn.close()
    
    # Clear form and refresh
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    vault_password_entry.delete(0, tk.END)
    notes_entry.delete("1.0", tk.END)
    refresh_vault()

def copy_to_clipboard():
    """Copy selected password to clipboard"""
    selected_item = vault_tree.focus()
    if selected_item:
        password = vault_tree.item(selected_item)['values'][2]
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard")

def generate_vault_password():
    """Generate a strong password for the vault"""
    vault_password_entry.delete(0, tk.END)
    vault_password_entry.insert(0, generate_strong_password())

def update_feedback(message, color):
    """Update feedback label"""
    feedback_label.config(text=message, fg=color)

def toggle_password_visibility():
    """Toggle password visibility"""
    global password_visibility
    password_visibility = not password_visibility
    if password_visibility:
        password_entry.config(show="")
        show_password_button.config(text="Hide Password")
    else:
        password_entry.config(show="•")
        show_password_button.config(text="Show Password")

def toggle_vault_password_visibility():
    """Toggle vault password visibility"""
    if vault_password_entry.cget('show') == '':
        vault_password_entry.config(show='•')
        show_vault_password_button.config(text="Show Password")
    else:
        vault_password_entry.config(show='')
        show_vault_password_button.config(text="Hide Password")

def toggle_dark_mode():
    """Toggle between dark and light mode"""
    global dark_mode
    dark_mode = not dark_mode
    
    bg_color = "#2d2d2d" if dark_mode else "white"
    fg_color = "white" if dark_mode else "black"
    entry_bg = "#3d3d3d" if dark_mode else "white"
    entry_fg = "white" if dark_mode else "black"
    button_bg = "#4d4d4d" if dark_mode else "#f0f0f0"
    
    root.config(bg=bg_color)
    login_frame.config(bg=bg_color)
    main_frame.config(bg=bg_color)
    
    for label in [email_label, password_label, otp_label, feedback_label, 
                 website_label, username_label, vault_password_label, notes_label]:
        label.config(bg=bg_color, fg=fg_color)
    
    for entry in [email_entry, password_entry, otp_entry, website_entry, 
                 username_entry, vault_password_entry]:
        entry.config(bg=entry_bg, fg=entry_fg, insertbackground=fg_color)
    
    notes_entry.config(bg=entry_bg, fg=entry_fg, insertbackground=fg_color)
    
    for button in [register_button, login_button, verify_button, resend_otp_button,
                  show_password_button, dark_mode_button, add_button, 
                  generate_button, copy_button, show_vault_password_button]:
        button.config(bg=button_bg, fg=fg_color)
    
    dark_mode_button.config(text="Light Mode" if dark_mode else "Dark Mode")

# GUI Setup
root = tk.Tk()
root.title("Password Manager Pro")
root.geometry("800x600")
root.minsize(600, 400)

# Style configuration
style = ttk.Style()
style.configure("Treeview", rowheight=25)
style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))

# Login Frame
login_frame = tk.Frame(root, bg="white")
login_frame.pack(fill=tk.BOTH, expand=True)

email_label = tk.Label(login_frame, text="Email:", bg="white")
email_label.pack(pady=5)

email_entry = tk.Entry(login_frame, width=40)
email_entry.pack(pady=5)

password_label = tk.Label(login_frame, text="Password:", bg="white")
password_label.pack(pady=5)

password_entry = tk.Entry(login_frame, show="•", width=40)
password_entry.pack(pady=5)

show_password_button = tk.Button(login_frame, text="Show Password", 
                                command=toggle_password_visibility)
show_password_button.pack(pady=5)

feedback_label = tk.Label(login_frame, text="", font=('Helvetica', 10), bg="white")
feedback_label.pack(pady=10)

register_button = tk.Button(login_frame, text="Register", command=register_user)
register_button.pack(pady=5, side=tk.LEFT, padx=10, expand=True)

login_button = tk.Button(login_frame, text="Login", command=login_user)
login_button.pack(pady=5, side=tk.RIGHT, padx=10, expand=True)

dark_mode_button = tk.Button(login_frame, text="Dark Mode", command=toggle_dark_mode)
dark_mode_button.pack(pady=10)

# OTP Verification Controls
otp_label = tk.Label(login_frame, text="Enter OTP:", bg="white")
otp_entry = tk.Entry(login_frame, width=40)
verify_button = tk.Button(login_frame, text="Verify OTP")
resend_otp_button = tk.Button(login_frame, text="Resend OTP")

# Initially hide OTP controls
for widget in [otp_label, otp_entry, verify_button, resend_otp_button]:
    widget.pack_forget()

# Main Application Frame (initially hidden)
main_frame = tk.Frame(root, bg="white")

# Password Vault Section
vault_frame = tk.Frame(main_frame)
vault_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Treeview for displaying passwords
vault_tree = ttk.Treeview(vault_frame, columns=("Website", "Username", "Password", "Notes"), 
                          show="headings", selectmode="browse")
vault_tree.heading("Website", text="Website")
vault_tree.heading("Username", text="Username")
vault_tree.heading("Password", text="Password")
vault_tree.heading("Notes", text="Notes")

vault_tree.column("Website", width=150)
vault_tree.column("Username", width=150)
vault_tree.column("Password", width=150)
vault_tree.column("Notes", width=250)

vault_tree.pack(fill=tk.BOTH, expand=True)

# Controls below the treeview
button_frame = tk.Frame(vault_frame)
button_frame.pack(fill=tk.X, pady=5)

copy_button = tk.Button(button_frame, text="Copy Password", command=copy_to_clipboard)
copy_button.pack(side=tk.LEFT, padx=5)

# Add Password Form
form_frame = tk.LabelFrame(main_frame, text="Add New Password")
form_frame.pack(fill=tk.X, padx=10, pady=10)

website_label = tk.Label(form_frame, text="Website:")
website_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)

website_entry = tk.Entry(form_frame, width=30)
website_entry.grid(row=0, column=1, padx=5, pady=5)

username_label = tk.Label(form_frame, text="Username:")
username_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)

username_entry = tk.Entry(form_frame, width=30)
username_entry.grid(row=1, column=1, padx=5, pady=5)

vault_password_label = tk.Label(form_frame, text="Password:")
vault_password_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)

vault_password_entry = tk.Entry(form_frame, show="•", width=30)
vault_password_entry.grid(row=2, column=1, padx=5, pady=5)

show_vault_password_button = tk.Button(form_frame, text="Show Password", 
                                     command=toggle_vault_password_visibility)
show_vault_password_button.grid(row=2, column=2, padx=5)

generate_button = tk.Button(form_frame, text="Generate", 
                           command=generate_vault_password)
generate_button.grid(row=2, column=3, padx=5)

notes_label = tk.Label(form_frame, text="Notes:")
notes_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.NE)

notes_entry = scrolledtext.ScrolledText(form_frame, width=30, height=3)
notes_entry.grid(row=3, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)

add_button = tk.Button(form_frame, text="Add to Vault", command=add_to_vault)
add_button.grid(row=4, column=1, pady=10)

# Initially hide main frame
main_frame.pack_forget()

root.mainloop()
