import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, PhotoImage
from datetime import datetime
import hashlib
import os
import ssl
from tkinter import font as tkfont
import random
import emoji 

HOST = '127.0.0.1'  # Update this if connecting to another machine
PORT = 12345
CERT_FILE = 'cert.pem'  # Server's certificate

class ModernChatClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat App")
        self.master.configure(bg="#f0f2f5")
        self.username = None
        self.users_colors = {}  # Dictionary to store user colors
        self.color_options = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#FFBE0B", "#FB5607", "#8338EC", "#3A86FF"]
        self.last_message_sender = None  # Track who sent the last message
        
        # Create socket and SSL context
        self.create_secure_connection()
        
        # Set up fonts
        self.default_font = tkfont.Font(family="Segoe UI", size=10)
        self.username_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.timestamp_font = tkfont.Font(family="Segoe UI", size=8)
        
        self.common_emojis = ["😊", "👍", "❤️", "😂", "🎉", "🤔", "👋", "😎"]

        # Create main frames
        self.create_header_frame()
        self.create_chat_frame()
        self.create_input_frame()
        self.create_emoji_frame()
        
        # Configure text tags
        self.configure_text_tags()
        
        # Show welcome message
        self.show_welcome_message()
        
        # Prompt for username
        self.prompt_username()
        
        # Start receiving messages
        threading.Thread(target=self.receive_messages, daemon=True).start()
        
        # Bind window resize
        self.master.bind("<Configure>", self.on_window_configure)
        
        # Bind close event
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_secure_connection(self):
        """Create a secure SSL connection to the server"""
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # For development: disable certificate verification
            # In production, you should use proper certificate validation
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create socket and wrap with SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = context.wrap_socket(sock, server_hostname=HOST)
            self.sock.connect((HOST, PORT))
            
            # Update status display to show secure connection
            self.connection_secure = True
        except Exception as e:
            print(f"Error establishing secure connection: {e}")
            # Fallback to non-secure connection
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            self.connection_secure = False

    def create_header_frame(self):
        """Create the header with app title and online status"""
        self.header_frame = tk.Frame(self.master, bg="#075E54", height=50)
        self.header_frame.pack(fill=tk.X)
        
        # App title
        title_label = tk.Label(self.header_frame, text="Secure Chat", font=("Segoe UI", 14, "bold"), 
                              bg="#075E54", fg="white")
        title_label.pack(side=tk.LEFT, padx=15, pady=10)
        
        # Security indicator
        self.security_indicator = tk.Label(self.header_frame, text="🔒", font=("Segoe UI", 12),
                                         bg="#075E54", fg="#4CAF50")
        self.security_indicator.pack(side=tk.LEFT, padx=0)
        
        # Online status indicator
        self.status_frame = tk.Frame(self.header_frame, bg="#075E54")
        self.status_frame.pack(side=tk.RIGHT, padx=15, pady=10)
        
        self.status_indicator = tk.Canvas(self.status_frame, width=10, height=10, 
                                        bg="#075E54", highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 5))
        self.status_indicator.create_oval(2, 2, 10, 10, fill="#4CAF50", outline="")
        
        self.status_label = tk.Label(self.status_frame, text="Online", 
                                   font=("Segoe UI", 9), bg="#075E54", fg="white")
        self.status_label.pack(side=tk.LEFT)

    def create_chat_frame(self):
        """Create the main chat display area"""
        chat_frame = tk.Frame(self.master, bg="#ECE5DD")
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Chat display with custom scrollbar
        self.text_area = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD, 
            state='disabled', 
            font=self.default_font, 
            bg="#ECE5DD",
            highlightthickness=0,
            bd=0,
            padx=10,
            pady=10
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Custom scrollbar styling
        self.text_area.vbar.configure(troughcolor="#ECE5DD", bg="#75a99c", width=8,
                                    activebackground="#128C7E")

    def create_input_frame(self):
        """Create the message input area"""
        input_frame = tk.Frame(self.master, bg="#f0f2f5", height=60)
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Message input field
        self.input_field = ttk.Entry(input_frame, font=("Segoe UI", 11))
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 5), pady=10, ipady=8)
        self.input_field.bind("<Return>", self.send_message)
        self.input_field.focus()

        # Emoji button
        self.emoji_button = ttk.Button(input_frame, text="😊", command=self.toggle_emoji_panel, style="Emoji.TButton")
        self.emoji_button.pack(side=tk.LEFT, padx=(0, 5), pady=10)
        
        # Send button
        self.send_button = ttk.Button(input_frame, text="Send", command=self.send_message, style="Send.TButton")
        self.send_button.pack(side=tk.RIGHT, padx=(0, 10), pady=10, ipadx=5)

        # Variable to track if emoji panel is visible
        self.emoji_panel_visible = False


    def configure_text_tags(self):
        """Configure text tags for styling messages"""
        # Base alignment tags
        self.text_area.tag_configure("self_msg", justify="right", lmargin1=50, rmargin=10)
        self.text_area.tag_configure("other_msg", justify="left", lmargin1=10, rmargin=50)
        
        # User and timestamp tags
        self.text_area.tag_configure("username", font=self.username_font)
        self.text_area.tag_configure("timestamp", font=self.timestamp_font, foreground="grey")
        
        # System message styling
        self.text_area.tag_configure("system_msg", justify="center", font=("Segoe UI", 9, "italic"), foreground="#888888")
        self.text_area.tag_configure("welcome", justify="center", font=("Segoe UI", 12, "bold"), foreground="#128C7E")
        
        # Security info tag
        self.text_area.tag_configure("security_info", justify="center", font=("Segoe UI", 9), foreground="#2E7D32")

    def show_welcome_message(self):
        """Display welcome message when app starts"""
        self.text_area.configure(state='normal')
        self.text_area.insert(tk.END, "\n✨ Welcome to Secure Chat ✨\n\n", "welcome")
        
        # Display security status
        if hasattr(self, 'connection_secure') and self.connection_secure:
            self.text_area.insert(tk.END, "🔒 Connection is encrypted with SSL\n", "security_info")
        else:
            self.text_area.insert(tk.END, "⚠️ Connection is NOT encrypted\n", "system_msg")
            
        self.text_area.insert(tk.END, "Please enter your username to join the conversation.\n\n", "system_msg")
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)

    def prompt_username(self):
        """Prompt user to enter username"""
        popup = tk.Toplevel(self.master)
        popup.title("Join Secure Chat")
        popup.geometry("300x180")
        popup.configure(bg="white")
        popup.resizable(False, False)
        popup.grab_set()  # Make window modal
        
        # Center the popup
        popup.update_idletasks()
        width = popup.winfo_width()
        height = popup.winfo_height()
        x = (popup.winfo_screenwidth() // 2) - (width // 2)
        y = (popup.winfo_screenheight() // 2) - (height // 2)
        popup.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        # Header
        header_frame = tk.Frame(popup, bg="#075E54", height=40)
        header_frame.pack(fill=tk.X)
        
        header_text = tk.Frame(header_frame, bg="#075E54")
        header_text.pack(pady=10)
        
        tk.Label(header_text, text="🔒", font=("Segoe UI", 12), 
                bg="#075E54", fg="#4CAF50").pack(side=tk.LEFT, padx=(0, 5))
                
        tk.Label(header_text, text="Join Secure Chat", font=("Segoe UI", 12, "bold"),
                bg="#075E54", fg="white").pack(side=tk.LEFT)
        
        # Content
        content_frame = tk.Frame(popup, bg="white")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(content_frame, text="Enter your username:", bg="white", 
                font=("Segoe UI", 10)).pack(anchor="w")
        
        entry = ttk.Entry(content_frame, font=("Segoe UI", 11))
        entry.pack(fill=tk.X, pady=(5, 15))
        entry.focus()
        
        # Set a random placeholder username
        placeholder = f"User{random.randint(1000, 9999)}"
        entry.insert(0, placeholder)
        entry.selection_range(0, len(placeholder))
        
        def save_username():
            username = entry.get().strip()
            if not username:
                return
            self.username = username
            self.sock.sendall(self.username.encode())
            popup.destroy()
            self.after_username_set()
        
        ttk.Button(content_frame, text="Join Chat", command=save_username, 
                  style="Join.TButton").pack(fill=tk.X)
        
        # Bind Enter key
        entry.bind("<Return>", lambda event: save_username())

    def after_username_set(self):
        """Update UI after username is set"""
        self.text_area.configure(state='normal')
        self.text_area.insert(tk.END, f"You've joined as {self.username}\n\n", "system_msg")
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)
        
        # Update window title with username
        self.master.title(f"Secure Chat - {self.username}")
        
        # Assign a color for this user
        self.users_colors[self.username] = self.get_color_for_user(self.username)

    def get_color_for_user(self, username):
        """Generate consistent color for a username"""
        if username not in self.users_colors:
            # Generate a hash from the username and use it to pick a color
            hash_obj = hashlib.md5(username.encode())
            hash_int = int(hash_obj.hexdigest(), 16)
            self.users_colors[username] = self.color_options[hash_int % len(self.color_options)]
        return self.users_colors[username]

    def generate_avatar(self, username, size=30):
        """Create an avatar image with user's initial on a colored background"""
        canvas = tk.Canvas(self.master, width=size, height=size, bg="white", highlightthickness=0)
        color = self.get_color_for_user(username)
        canvas.create_oval(2, 2, size-2, size-2, fill=color, outline="")
        
        initial = username[0].upper()
        canvas.create_text(size//2, size//2, text=initial, fill="white", 
                          font=("Segoe UI", int(size/2), "bold"))
        
        return canvas

    def receive_messages(self):
        """Receive messages from the server"""
        while True:
            try:
                message = self.sock.recv(1024).decode()
                if message:
                    if ":" in message:
                        # Regular message with username prefix
                        username, content = message.split(":", 1)
                        self.display_other_message(username, content)
                    elif message.startswith("***"):
                        # System message
                        self.display_system_message(message)
                    else:
                        # Other messages
                        self.display_system_message(message)
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.display_system_message("⚠️ Connection to server lost. Please restart the app.")
                break

    
    def create_emoji_frame(self):
        """Create the emoji selection panel"""
        self.emoji_frame = tk.Frame(self.master, bg="white", bd=1, relief=tk.SOLID)
        
        # Create a frame for the emoji grid
        emoji_grid = tk.Frame(self.emoji_frame, bg="white")
        emoji_grid.pack(padx=5, pady=5)
        
        # Add emoji buttons in a grid
        row, col = 0, 0
        for emoji_char in self.common_emojis:
            btn = tk.Button(emoji_grid, text=emoji_char, font=("Segoe UI", 14), bd=0,
                          bg="white", activebackground="#f0f2f5", width=2, height=1,
                          command=lambda e=emoji_char: self.insert_emoji(e))
            btn.grid(row=row, column=col, padx=2, pady=2)
            col += 1
            if col > 3:  # 4 emojis per row
                col = 0
                row += 1
        
        # Add a text entry for searching emojis
        search_frame = tk.Frame(self.emoji_frame, bg="white")
        search_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        search_label = tk.Label(search_frame, text="Find:", bg="white", font=("Segoe UI", 9))
        search_label.pack(side=tk.LEFT)
        
        self.emoji_search = ttk.Entry(search_frame, font=("Segoe UI", 9))
        self.emoji_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.emoji_search.bind("<Return>", self.search_emoji)
        
        search_btn = ttk.Button(search_frame, text="🔍", style="Emoji.TButton", 
        command=self.search_emoji)
        search_btn.pack(side=tk.RIGHT)

    def toggle_emoji_panel(self):
        """Show or hide the emoji selection panel"""
        if self.emoji_panel_visible:
            self.emoji_frame.place_forget()
            self.emoji_panel_visible = False
        else:
            # Position emoji panel above the input field
            x = self.emoji_button.winfo_rootx() - self.master.winfo_rootx()
            y = self.emoji_button.winfo_rooty() - self.master.winfo_rooty() - self.emoji_frame.winfo_reqheight()
            self.emoji_frame.place(x=x, y=y)
            self.emoji_panel_visible = True

    def insert_emoji(self, emoji_char):
        """Insert the selected emoji into the input field"""
        current_text = self.input_field.get()
        cursor_pos = self.input_field.index(tk.INSERT)
        new_text = current_text[:cursor_pos] + emoji_char + current_text[cursor_pos:]
        self.input_field.delete(0, tk.END)
        self.input_field.insert(0, new_text)
        self.input_field.icursor(cursor_pos + len(emoji_char))
        self.input_field.focus()

    def search_emoji(self, event=None):
        """Search for emoji by keyword"""
        search_term = self.emoji_search.get().strip().lower()
        if not search_term:
            return
            
        # Use emoji library to find matching emojis
        try:
            matching_emojis = []
            for emoji_name, emoji_char in emoji.EMOJI_UNICODE_ENGLISH.items():
                if search_term in emoji_name.lower():
                    matching_emojis.append(emoji_char)
                    if len(matching_emojis) >= 8:  # Limit results
                        break
                        
            # If matches found, update emoji buttons
            if matching_emojis:
                # Clear existing emoji grid
                for widget in self.emoji_frame.winfo_children()[0].winfo_children():
                    widget.destroy()
                
                # Add new emoji buttons
                row, col = 0, 0
                for emoji_char in matching_emojis:
                    btn = tk.Button(self.emoji_frame.winfo_children()[0], text=emoji_char, 
                                  font=("Segoe UI", 14), bd=0, bg="white", 
                                  activebackground="#f0f2f5", width=2, height=1,
                                  command=lambda e=emoji_char: self.insert_emoji(e))
                    btn.grid(row=row, column=col, padx=2, pady=2)
                    col += 1
                    if col > 3:
                        col = 0
                        row += 1
        except Exception as e:
            print(f"Error searching emojis: {e}")

    def send_message(self, event=None):
        """Send message to the server with emoji conversion"""
        message = self.input_field.get().strip()
        if message:
            # Convert shortcodes to emojis
            try:
                message = emoji.emojize(message, language='alias')
            except:
                pass  # If conversion fails, use original message
                
            self.sock.sendall(message.encode())
            self.display_self_message(message)
            self.input_field.delete(0, tk.END)
            
            if message.lower() == "exit":
                self.on_close()

    def display_self_message(self, message):
        """Display message sent by current user"""
        self.text_area.configure(state='normal')
        
        # Add newline if needed
        if self.text_area.index('end-1c') != '1.0' and not self.text_area.get('end-1c linestart', 'end-1c').isspace():
            self.text_area.insert(tk.END, "\n")
        
        # Insert message without bubble styling
        self.text_area.insert(tk.END, f"{message}\n", "self_msg")
        
        # Add timestamp in a smaller font below the message
        timestamp = datetime.now().strftime("%H:%M")
        self.text_area.insert(tk.END, f"{timestamp}\n\n", "self_msg timestamp")
        
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)
        
    def display_other_message(self, username, content):
        """Display message from another user"""
        if username == self.username:
            return  # Skip messages from ourselves (already displayed)
            
        self.text_area.configure(state='normal')
        
        # Add newline if needed
        if self.text_area.index('end-1c') != '1.0' and not self.text_area.get('end-1c linestart', 'end-1c').isspace():
            self.text_area.insert(tk.END, "\n")
        
        # Set color for this user
        user_color = self.get_color_for_user(username)
        self.text_area.tag_configure(f"username_{username}", foreground=user_color, font=self.username_font)
        
        # Insert username with color
        self.text_area.insert(tk.END, f"{username}\n", f"other_msg username_{username}")
        
        # Insert message without bubble styling
        self.text_area.insert(tk.END, f"{content}\n", "other_msg")
        
        # Add timestamp
        timestamp = datetime.now().strftime("%H:%M")
        self.text_area.insert(tk.END, f"{timestamp}\n\n", "other_msg timestamp")
        
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)

    def display_system_message(self, message):
        """Display system message (join/leave notifications, etc.)"""
        self.text_area.configure(state='normal')
        
        # Add newline if needed
        if self.text_area.index('end-1c') != '1.0' and not self.text_area.get('end-1c linestart', 'end-1c').isspace():
            self.text_area.insert(tk.END, "\n")
            
        # Display system message
        self.text_area.insert(tk.END, f"{message}\n\n", "system_msg")
        
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)

    def on_window_configure(self, event=None):
        """Handle window resize"""
        # Update text display on window resize
        self.text_area.see(tk.END)
    
    def on_close(self):
        """Clean up when window is closed"""
        try:
            self.sock.sendall("exit".encode())
            self.sock.close()
        except:
            pass
        self.master.destroy()



def setup_styles():
    """Set up custom ttk styles"""
    style = ttk.Style()
    
    # Use a modern theme as base
    try:
        style.theme_use("clam")
    except:
        pass  # Fallback to default if clam not available
    
    # Input field style
    style.configure("TEntry", 
                  padding=10, 
                  relaief="flat", 
                  borderwidth=0,
                  background="white")
    
    # Send button style
    style.configure("Send.TButton", 
                  padding=8, 
                  relief="flat", 
                  background="#128C7E", 
                  foreground="white")
    style.map("Send.TButton", 
            background=[("active", "#075E54")],
            foreground=[("active", "white")])
    
    # Emoji button style
    style.configure("Emoji.TButton", 
                  padding=8, 
                  relief="flat", 
                  background="#f0f2f5")
    style.map("Emoji.TButton", 
            background=[("active", "#e0e0e0")])
    
    # Join button style
    style.configure("Join.TButton", 
                  padding=10, 
                  relief="flat", 
                  background="#128C7E", 
                  foreground="white")
    style.map("Join.TButton", 
            background=[("active", "#075E54")],
            foreground=[("active", "white")])



if __name__ == "__main__":
    root = tk.Tk()
    setup_styles()
    
    # Set minimum window size
    root.minsize(400, 500)
    
    # Create the chat client
    client = ModernChatClientGUI(root)
    
    # Set window size and position
    root.geometry("500x700")
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    # Start the app
    root.mainloop()