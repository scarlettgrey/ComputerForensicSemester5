import tkinter as tk
from tkinter import ttk,filedialog
from Crypto.Cipher import AES
import hashlib,string,os,random
import HDDRecov
import wmi
import subprocess

w = wmi.WMI()

window = tk.Tk()
window.title("BitRecov")
window.geometry("600x400")

Ptab = ttk.Notebook(window)

Letter = ['A:','B:','C:','D:','E:','F:','G:','H:','I:','J:','K:','L:','M:','N:','O:','P:','Q:','R:','S:','T:','U:','V:','W:','X:','Y:','Z:']
OccupiedDrivesLetter = ['%s:'%d for d in string.ascii_uppercase if os.path.exists('%s:'%d)]
AvailableDrivesLetter = []
for a in Letter:
    if a not in OccupiedDrivesLetter:
        AvailableDrivesLetter.append(a)

def printselecteddisk():
    saverecoveredfile = EntrySaveDiskHDDRecov.get()
    seldisk = EntryTargetDiskHDDRecov.get()
    for physical_disk in w.Win32_DiskDrive():
        for partition in physical_disk.associators("Win32_DiskDriveToDiskPartition"):
            for logical in partition.associators("Win32_LogicalDiskToPartition"):
                if logical.Caption == seldisk:
                    hd = partition.Caption[6]
                    par = int(partition.Caption[20]) + 1
                    hdpar = '\\\\.\\'
                    listofdisk = [hdpar + "harddisk" + hd + "partition" + str(par), '--pattern', '*', '--outdir', saverecoveredfile]
                    # pipe = subprocess.Popen(HDDRecov.main(listofdisk),stdout=subprocess.PIPE)
                    # text = pipe.communicate()[0]
                    # subprocess.call("py HDDRecov.py " + hdpar + "harddisk" + hd + "partition" + str(par) + " --pattern \"*\" --outdir \"C:\\Users\\ferdi\\Desktop\\Semester 5\\Computer Forensic\\Projek\\Recovered\"")

def opensavetoHDDRecov():
    SaveToPath = filedialog.askdirectory()
    if SaveToPath:
        EntrySaveDiskHDDRecov.insert(0,SaveToPath)

tabHDD = tk.Frame(Ptab)
Ptab.add(tabHDD,text="HDD Reovery")
LabelTargetDiskHDDRecov = tk.Label(tabHDD,text="Target Disk: ")
LabelTargetDiskHDDRecov.grid(row=0,column=0,pady=5,sticky="W")
EntryTargetDiskHDDRecov = ttk.Combobox(tabHDD,values=OccupiedDrivesLetter)
EntryTargetDiskHDDRecov.grid(row=0,column=1,columnspan=2,ipadx=25,sticky="E")
LabelSaveDiskHDDRecov = tk.Label(tabHDD,text="Save to ")
LabelSaveDiskHDDRecov.grid(row=1,column=0,pady=5,sticky="W")
EntrySaveDiskHDDRecov = tk.Entry(tabHDD)
EntrySaveDiskHDDRecov.grid(row=1,column=1,columnspan=2,ipadx=25,sticky="E")
tk.Button(tabHDD,text="...",command=opensavetoHDDRecov).grid(row=1,column=2,ipadx=5,pady=5,sticky="E")
tk.Checkbutton(tabHDD,text="Generate Report").grid(row=2,column=0,columnspan=2,sticky="W")
tk.Button(tabHDD,text="Start Recovery",command=printselecteddisk).grid(row=2,column=2,sticky="E")

tabPartition = tk.Frame(Ptab)
Ptab.add(tabPartition,text="Partition Tools")
EntryPartition = tk.Entry(tabPartition)
EntryPartition.grid(row=0,ipadx=200,columnspan=4,pady=5,sticky="W")
tk.Button(tabPartition,text="Dump Partition").grid(row=1,column=0,ipadx=14,sticky="W")
LabelRenamePartition = tk.Label(tabPartition,text="Rename")
LabelRenamePartition.grid(row=1,column=1)
EntryRenamePartition = tk.Entry(tabPartition)
EntryRenamePartition.grid(row=1,column=2,columnspan=2,ipadx=78,sticky="W")
tk.Radiobutton(tabPartition,text="Primary Partition",value="Primary").grid(row=3,column=0,pady=5,sticky="W")
tk.Radiobutton(tabPartition,text="Extended Partition",value="Extended").grid(row=3,column=1,pady=5,sticky="W")
LabelSizePartition = tk.Label(tabPartition,text="Size(in MB): ")
LabelSizePartition.grid(row=4,column=0,sticky="W")
EntrySizePartition = tk.Entry(tabPartition)
EntrySizePartition.grid(row=4,column=0,columnspan=2,ipadx=25,sticky="E")
LabelPartitionLetter = tk.Label(tabPartition,text="Partition Letter: ")
LabelPartitionLetter.grid(row=4,column=2,sticky="W")
EntryPartitionLetter = ttk.Combobox(tabPartition,values=AvailableDrivesLetter)
EntryPartitionLetter.grid(row=4,column=2,columnspan=2,ipadx=25,sticky="E")
tk.Checkbutton(tabPartition,text="Generate Report").grid(row=5,column=0)
tk.Button(tabPartition,text="Execute").grid(row=5,column=3,sticky="E")

tabFormat = tk.Frame(Ptab)
Ptab.add(tabFormat,text="Format")
LabelTargetDiskFormat = tk.Label(tabFormat,text="Target Disk/Partition: ")
LabelTargetDiskFormat.grid(row=0,column=0,pady=5)
EntryTargetDiskFormat = ttk.Combobox(tabFormat,values=OccupiedDrivesLetter)
EntryTargetDiskFormat.grid(row=0,column=1,columnspan=2,ipadx=25,sticky="E")
tk.Checkbutton(tabFormat,text="Generate Report").grid(row=1,column=0)
tk.Button(tabFormat,text="Start Format").grid(row=1,column=2,sticky="E")

EncDecType = ['AES','RSA']

def openfileEnc():
    EncFile = filedialog.askopenfile(parent=tabEnc,mode="rb")
    if EncFile:
        EntryTargetDataEnc.insert(0,EncFile.name)

# def LetsEncrypt():
#     key = ''
#     iv = ''
#     for a in range(256):
#         key += str(random.randint(0,9))
#     for a in range(16):
#         iv += str(random.randint(0,9))

#     if EntryEncType.get() == 'AES':
#         pass
#     elif EntryEncType.get() == 'RSA':
#         pass
#     else:
#         pass

tabEnc = tk.Frame(Ptab)
Ptab.add(tabEnc,text="Encryption")
LabelTargetDataEnc = tk.Label(tabEnc,text="Target Data: ")
LabelTargetDataEnc.grid(row=0,column=0,pady=5,sticky="W")
EntryTargetDataEnc = tk.Entry(tabEnc)
EntryTargetDataEnc.grid(row=0,column=1,columnspan=2,ipadx=144,pady=5,sticky="E")
tk.Button(tabEnc,text="...",command=openfileEnc).grid(row=0,column=2,ipadx=5,pady=5,sticky="E")
LabelEncType = tk.Label(tabEnc,text="Encrytption Type: ")
LabelEncType.grid(row=1,column=0,sticky="W")
EntryEncType = ttk.Combobox(tabEnc,values=EncDecType)
EntryEncType.grid(row=1,column=1,columnspan=2,ipadx=135,sticky="E")
tk.Checkbutton(tabEnc,text="Generate Report").grid(row=2,column=0,pady=5)
tk.Button(tabEnc,text="Encrypt").grid(row=2,column=2,pady=5,sticky="E")

def openfileDec():
    DecFile = filedialog.askopenfile(parent=tabDec,mode="rb")
    if DecFile:
        EntryTargetDataDec.insert(0,DecFile.name)

tabDec = tk.Frame(Ptab)
Ptab.add(tabDec,text="Decryption")
LabelTargetDataDec = tk.Label(tabDec,text="Target Data: ")
LabelTargetDataDec.grid(row=0,column=0,pady=5,sticky="W")
EntryTargetDataDec = tk.Entry(tabDec)
EntryTargetDataDec.grid(row=0,column=1,columnspan=2,ipadx=144,pady=5,sticky="E")
tk.Button(tabDec,text="...",command=openfileDec).grid(row=0,column=2,ipadx=5,pady=5,sticky="E")
LabelDecType = tk.Label(tabDec,text="Decrytption Type: ")
LabelDecType.grid(row=1,column=0,sticky="W")
EntryDecType = ttk.Combobox(tabDec,values=EncDecType)
EntryDecType.grid(row=1,column=1,columnspan=2,ipadx=135,sticky="E")
tk.Checkbutton(tabDec,text="Generate Report").grid(row=2,column=0,pady=5)
tk.Button(tabDec,text="Decrypt").grid(row=2,column=2,pady=5,sticky="E")

Ptab.pack(expand=1,fill="both")

window.mainloop() 
