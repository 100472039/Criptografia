from tkinter import *
import creador

def register_user():
    username_info = username.get()
    password_info = password.get()

    print(username)
    print(username_info)

    """
    file = open(username_info+".txt", "w")
    file.write(username_info+"\n")
    file.write(password_info)
    file.close()
    """

    creador.registrar(username_info, password_info)

    username_entry.delete(0, END)
    password_entry.delete(0, END)

    Label(screen1, text="Éxito al registrarse", fg="green", font=("Calibri", 11)).pack()

def register():
    global username
    global password
    global username_entry
    global password_entry
    global screen1
    screen1 = Toplevel(screen)
    screen1.title("Register")
    screen1.geometry("300x250")

    username = StringVar()
    password = StringVar()

    Label(screen1, text="Enter details below").pack()
    Label(screen1, text="").pack()
    Label(screen1, text="Username * ").pack()
    username_entry = Entry(screen1, textvariable=username)
    username_entry.pack()
    Label(screen1, text="Password * ").pack()
    password_entry = Entry(screen1, textvariable=password)
    password_entry.pack()
    Button(screen1, text="Register", width=10, height=1, command=register_user).pack()


def login():
    print("Login session started")

def main_screen():
    global screen
    screen = Tk()
    screen.geometry("300x250")
    screen.title("Notes 1.0")

    button_height = 2
    button_width = 30

    Label(text = "Notes 1.0", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Login", height=button_height, width=button_width, command=login).pack()
    Label(text="").pack()
    Button(text="Register", height=button_height, width=button_width, command=register).pack()


    screen.mainloop()

main_screen()