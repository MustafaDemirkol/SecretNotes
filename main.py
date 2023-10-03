import base64
import tkinter
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk


my_window = Tk()
my_window.title("SecretNotes")
my_window.minsize(450,750)
my_window.config(padx=50, pady=50)

# get image
img = Image.open("topSecret.png")
resized_img = img.resize((100, 100))
new_image = ImageTk.PhotoImage(resized_img)

# image label
topsecret_label = Label(my_window, image=new_image)
topsecret_label.pack()

# input note name
note_name_label = Label(text="Enter Your Title")
note_name_label.config(padx=10,pady=10)
note_name_label.pack()
note_name_entry = Entry(width=40)
note_name_entry.pack()

# input note
note_field_label = Label(text="Enter Your Note")
note_field_label.config(padx=10,pady=10)
note_field_label.pack()
note_field_Text = Text(width=30, height=20)
note_field_Text.pack()

# input key to encrypt and decrypt
master_key_label = Label(text="Enter Your Password")
master_key_label.config(padx=10,pady=10)
master_key_label.pack()
master_key_entry = Entry(width=40, show="*")
master_key_entry.pack()


# writing file
def write_file(file_path="", message_name="", encrypted_message=""):

    with open(file_path, 'a') as file:
        file.write(message_name+":\n")
        file.write(encrypted_message+"\n")


# encode and decode functions
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


# button functions
def encrypt_note():
    message_name = note_name_entry.get()
    message_to_crypt = note_field_Text.get("1.0", END)
    password = master_key_entry.get()

    if len(message_name) == 0 or len(message_to_crypt) <= 1 or len(password) == 0:
        messagebox.showinfo(title="Error!", message="Please Enter all information")
        # len(message_to_crypt) <= 1  -> because of len(message_to_crypt) = 1 when text field is empty

    else:
        try:
            encoded_message = encode(password, message_to_crypt)

            write_file("SecretNotes.txt", note_name_entry.get(), encoded_message)

            note_name_entry.delete(0, END)
            note_field_Text.delete("1.0", END)
            master_key_entry.delete(0, END)

            messagebox.showinfo(title="Encryption is Successful", message="Your message successfully encrypted an saved\n in SecretNotes.txt file")
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of Enter all information correctly!")


def decrypt_note():

    message_to_decrypt = note_field_Text.get("1.0", END)
    password = master_key_entry.get()

    if len(message_to_decrypt) <= 1 or len(password) == 0:
        messagebox.showinfo(title="ERROR!", message="Please Enter an encrypted note and password!")
    else:
        try:
            decoded_message = decode(password, message_to_decrypt)

            note_field_Text.delete("1.0", END)
            master_key_entry.delete(0, END)

            note_field_Text.insert("1.0", decoded_message)
        except:
            messagebox.showinfo(title="Error!", message="Enter an Encrypted message to decrypt!")


save_encrypt_button = Button(text="Save&Encrypt", command=encrypt_note)
save_encrypt_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt_note)
decrypt_button.pack()





my_window.mainloop()

