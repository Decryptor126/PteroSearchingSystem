#!/usr/bin/env python3
#-*- coding: utf-8 -*-


__author__ = 'emothwei'

from hashlib import sha3_256, shake_256, blake2s
from SM3 import Hash_sm3 as SM3
from tkinter import *
import tkinter.messagebox as messagebox

'''
   SHA3 BLAKE2 SHAKE SM3
   
   root   SHA3(BLAKE2(SHAKE()))
   
   node1   BLAKE2(SHAKE(SM3()))       leaf1   SHAKE(SM3(SHA3()))
   
   node2   SM3(SHA3(BLAKE2()))        leaf2   SM3(SHAKE(BLAKE2()))
   
   leaf4   SHAKE(BLAKE2(SHA3()))      leaf3   BLAKE2(SHA3(SM3()))
'''

def SHA3(value):
    return sha3_256(value.encode('utf-8')).hexdigest()
    
def BLAKE2(value):
    return blake2s(value.encode('utf-8')).hexdigest()
    
def SHAKE(value):
    SHAKE_LENGTH = 32
    return shake_256(value.encode('utf-8')).hexdigest(SHAKE_LENGTH)
    

class Application(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()

    def createWidgets(self):
        self.v = IntVar()
        self.R1 = Radiobutton(self, text="top secret", variable = self.v, value = 1)
        self.R1.pack()
        self.R2 = Radiobutton(self, text="confidential", variable = self.v, value = 2)
        self.R2.pack()
        self.R3 = Radiobutton(self, text="secret", variable = self.v, value = 3)
        self.R3.pack()
        self.R4 = Radiobutton(self, text="public", variable = self.v, value = 4)
        self.R4.pack()
        
        self.Label1 = Label(self, text='value root: ')
        self.Label1.pack()
        self.nameInput1 = Entry(self)
        self.nameInput1.pack()
        self.Label2 = Label(self, text='value 1: ')
        self.Label2.pack()
        self.nameInput2 = Entry(self)
        self.nameInput2.pack()
        self.Label3 = Label(self, text='value 2 or hashed node1: ')
        self.Label3.pack()
        self.nameInput3 = Entry(self)
        self.nameInput3.pack()
        self.Label4 = Label(self, text='value 3 or hashed node2: ')
        self.Label4.pack()
        self.nameInput4 = Entry(self)
        self.nameInput4.pack()
        self.Label5 = Label(self, text='value 4 or hashed value4: ')
        self.Label5.pack()
        self.nameInput5 = Entry(self)
        self.nameInput5.pack()
        self.alertButton1 = Button(self, text='Verify', command=self.verify)
        self.alertButton1.pack()
        self.alertButton2 = Button(self, text='Quit', command=self.quit)
        self.alertButton2.pack()

    def verify(self):
        valueroot = self.nameInput1.get()
        value1 = self.nameInput2.get()
        value2 = self.nameInput3.get()
        value3 = self.nameInput4.get()
        value4 = self.nameInput5.get()
        node_root = ''
        SALT = 'BUHUIQIANDUAN'
        
        # top secret   Return value1 value2 value3 value4 valueroot
        if(self.v.get() == 1):
            value4 = SHAKE(BLAKE2(SHA3(value4 + SALT)))
            value3 = BLAKE2(SHA3(SM3(value3 + SALT)))
            value2 = SM3(SHAKE(BLAKE2(value2 + SALT)))
            value1 = SHAKE(SM3(SHA3(value1 + SALT)))
            node2 = SM3(SHA3(BLAKE2(value4 + value3)))
            node1 = BLAKE2(SHAKE(SM3(node2 + value2)))
            node_root = SHA3(BLAKE2(SHAKE(node1 + value1)))
            
        # confidential   Return hash(value4) value1 value2 value3 valueroot
        elif(self.v.get() == 2):
            value3 = BLAKE2(SHA3(SM3(value3 + SALT)))
            value2 = SM3(SHAKE(BLAKE2(value2 + SALT)))
            value1 = SHAKE(SM3(SHA3(value1 + SALT)))
            node2 = SM3(SHA3(BLAKE2(value4 + value3)))
            node1 = BLAKE2(SHAKE(SM3(node2 + value2)))
            node_root = SHA3(BLAKE2(SHAKE(node1 + value1)))
            
        # secret   Return node2=hash(value4 || value3) value2 value1 valueroot
        elif(self.v.get() == 3):
            value2 = SM3(SHAKE(BLAKE2(value2 + SALT)))
            value1 = SHAKE(SM3(SHA3(value1 + SALT)))
            node1 = BLAKE2(SHAKE(SM3(value3 + value2)))
            node_root = SHA3(BLAKE2(SHAKE(node1 + value1)))
            
        # public   Return node1=hash(node2 || value2) value1 valueroot
        else:
            value1 = SHAKE(SM3(SHA3(value1 + SALT)))
            node_root = SHA3(BLAKE2(SHAKE(value2 + value1)))
            
        if (node_root == valueroot):
            messagebox.showinfo('Congratulations', 'Data is correct')
        else:
            messagebox.showinfo('Bad news','Data has been tampered')
                

app = Application()
# window title:
app.master.title('Validator by emothwei')
app.master.geometry('300x450')
app.mainloop()