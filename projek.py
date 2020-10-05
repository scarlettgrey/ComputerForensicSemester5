from __future__ import unicode_literals, print_function
import struct
import collections
import glob
import fnmatch
import os
import sys
import codecs

def doseek(f, n):
    if sys.platform == 'win32':
        # Windows raw disks can only be seeked to a multiple of the block size
        BLOCKSIZE = 512
        na, nb = divmod(n, BLOCKSIZE)
        f.seek(na * BLOCKSIZE)
        if nb:
            f.read(nb)
    else:
        f.seek(n)

def readat(f, n, s):
    pos = f.tell()
    doseek(f, n)
    res = f.read(s)
    doseek(f, pos)
    return res

def parseFilename(s):
    ref, = struct.unpack('<Q', s[:8])
    flen = ord(s[64:65])
    fn = s[66:66 + flen*2].decode('UTF-16-LE')
    return ref, fn

def parseRaw(s):
    return s

ATTR_INFO = {
     0x10: ('standard_info', 'STANDARD_INFORMATION ', None),
     0x20: ('attr_list', 'ATTRIBUTE_LIST ', None),
     0x30: ('filename', 'FILE_NAME ', parseFilename),
     0x40: ('vol_ver', 'VOLUME_VERSION', None),
     0x40: ('obj_id', 'OBJECT_ID ', None),
     0x50: ('security', 'SECURITY_DESCRIPTOR ', None),
     0x60: ('vol_name', 'VOLUME_NAME ', None),
     0x70: ('vol_info', 'VOLUME_INFORMATION ', None),
     0x80: ('data', 'DATA ', None),
     0x90: ('index_root', 'INDEX_ROOT ', None),
     0xA0: ('index_alloc', 'INDEX_ALLOCATION ', None),
     0xB0: ('bitmap', 'BITMAP ', None),
     0xC0: ('sym_link', 'SYMBOLIC_LINK', None),
     0xC0: ('reparse', 'REPARSE_POINT ', None),
     0xD0: ('ea_info', 'EA_INFORMATION ', None),
     0xE0: ('ea', 'EA ', None),
     0xF0: ('prop_set', 'PROPERTY_SET', None),
    0x100: ('log_util', 'LOGGED_UTILITY_STREAM', None),
}

def parse_varint(v):
    if not v:
        return 0
    return int(codecs.encode(v[::-1], 'hex'), 16)

def read_runlist(f, bpc, runlist):
    out = bytearray()
    for rlen, roff in runlist:
        out += readat(f, roff * bpc, rlen * bpc)
    return bytes(out)

def parse_attr(f, bpc, chunk):
    type, size, nonres, namelen, nameoff = struct.unpack('<iiBBH', chunk[:12])

    if namelen:
        name = chunk[nameoff:nameoff+namelen*2].decode('UTF-16-LE')
    else:
        name = None

    stype, sname, sparser = ATTR_INFO.get(type, ('unk_%d' % type, str(type), parseRaw))
    if sparser is None:
        sparser = parseRaw
    sname = sname.strip()

    if nonres:
        rloff = struct.unpack('<H', chunk[32:34])[0]
        size_actual = struct.unpack('<Q', chunk[48:56])[0]
        rlpos = rloff
        runlist = []
        curoff = 0
        while rlpos < len(chunk):
            header = ord(chunk[rlpos:rlpos+1])
            if not header:
                break
            rlpos += 1
            lenlen = header & 0xf
            offlen = header >> 4
            if rlpos + lenlen + offlen > len(chunk):
                TextReportingHDDRecov.insert(tk.END,"Warning: invalid runlist header %02x (runlist %s)\n" % (header, codecs.encode(chunk[rloff:], 'hex')))
                break
            thislen = parse_varint(chunk[rlpos:rlpos+lenlen])
            rlpos += lenlen
            thisoff = parse_varint(chunk[rlpos:rlpos+offlen])
            if thisoff and (thisoff & (1 << (8 * offlen - 1))):
                thisoff -= 1 << (8 * offlen)
            rlpos += offlen
            curoff += thisoff
            runlist.append((thislen, curoff))

        attrdata = lambda: sparser(read_runlist(f, bpc, runlist)[:size_actual])
    else:
        attrlen, attroff = struct.unpack('<IH', chunk[16:22])
        data = chunk[attroff:attroff+attrlen]
        attrdata = lambda: sparser(data)

    return sname, name, attrdata

def usa_fixup(chunk, chunkoff, usa_ofs, usa_count):
    chunk = bytearray(chunk)
    if usa_ofs == 0 or usa_count == 0:
        return chunk

    upos = usa_ofs
    usa_num = chunk[upos:upos+2]
    upos += 2
    for i in range(len(chunk) // 512):
        cpos = i*512+510
        if chunk[cpos:cpos+2] != usa_num:
            TextReportingHDDRecov.insert(tk.END,"Warning: bad USA data at MBR offset %d - disk corrupt?\n" % (chunkoff + cpos))
        else:
            chunk[cpos:cpos+2] = chunk[upos:upos+2]
        upos += 2
    return chunk

def parse_file(f, chunkoff, bpc, chunk):
    magic, usa_ofs, usa_count, lsn, seq, link, attr_offset = struct.unpack(
        '<IHHQHHH', chunk[:22])
    attrs = collections.defaultdict(dict)
    try:
        chunk = usa_fixup(chunk, chunkoff, usa_ofs, usa_count)
    except Exception as e:
        TextReportingHDDRecov.insert(tk.END,"File at offset %d: failed to perform USA fixup: %s\n" % (chunkoff, e))

    pos = attr_offset
    while 1:
        if pos > len(chunk) - 12:
            # Uhoh, corruption?
            break
        type, size, nonres, namelen, nameoff = struct.unpack('<iIBBH', chunk[pos:pos+12])
        if type == -1:
            break

        try:
            sname, name, data = parse_attr(f, bpc, chunk[pos:pos+size])
            attrs[sname][name] = data
        except Exception as e:
            TextReportingHDDRecov.insert(tk.END,"File at offset %d: failed to parse attr type=%d pos=%d: %s\n" % (chunkoff, type, pos, e))

        pos += size
    return attrs

def parse_mft(f, bpc, mft):
    out = []
    for i in range(len(mft) // 1024):
        if i % 791 == 0:
            TextReportingHDDRecov.insert(tk.END,"Parsing MFT: %d/%d\n" % (i, len(mft) // 1024))
            sys.stderr.flush()

        chunk = mft[i*1024:(i+1)*1024]
        if chunk[:4] == b'FILE':
            out.append(parse_file(f, i * 1024, bpc, chunk))
        else:
            out.append(None)
    TextReportingHDDRecov.insert(tk.END,"Parsing MFT: Done!\n")
    sys.stderr.flush()
    return out

def read_mft(f, bpc, mft_cluster, clusters_per_mft):
    TextReportingHDDRecov.insert(tk.END,"Loading MBR from cluster %d\n" % mft_cluster)
    mft = readat(f, mft_cluster * bpc, clusters_per_mft * bpc)
    try:
        mftattr = parse_file(f, 0, bpc, mft[:1024])
        newmft = mftattr['DATA'][None]()
        if len(newmft) < len(mft):
            raise Exception("$MFT truncated")
        mft = newmft
    except Exception as e:
        TextReportingHDDRecov.insert(tk.END,"WARNING: Failed to load $MFT (%s), proceeding with partial MFT.\n" % e)

    return mft
    
def get_filepath(mft, i):
    bits = []
    while 1:
        parent, name = mft[i]['FILE_NAME'][None]()
        if name == '.':
            break
        bits.append(name)
        i = parent & 0xffffffffffff
    return bits[::-1]

def open_output_file(destfn):
    if not os.path.isfile(destfn):
        return open(destfn, 'wb')

    t = 0
    while True:
        fn = destfn + '_%04d' % t
        if not os.path.isfile(fn):
            return open(fn, 'wb')
        t += 1
    raise OSError("File exists.")

def save_file(mfti, destfn):
    if '/' in destfn:
        try:
            os.makedirs(destfn.rsplit('/', 1)[0])
        except OSError:
            pass

    with open_output_file(destfn) as outf:
        outf.write(mfti['DATA'][None]())

    for ads in mfti['DATA']:
        if ads is None:
            continue
        with open_output_file(destfn + '~' + ads) as outf:
            outf.write(mfti['DATA'][ads]())

def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Recover files from an NTFS volume")
    parser.add_argument('--sector-size', type=int,
        help='Sector size in bytes (default: trust filesystem)')
    parser.add_argument('--cluster-size', type=int,
        help='Cluster size in sectors (default: trust filesystem)')
    parser.add_argument('--mft', type=argparse.FileType('rb'),
        help='Use given file as MFT')
    parser.add_argument('--save-mft', type=argparse.FileType('wb'),
        help='Write extracted MFT to given file')
    parser.add_argument('-p', '--pattern', action='append',
        help='Recover files matching pattern (glob()); can be specified multiple times')
    parser.add_argument('-o', '--outdir',
        help='Output directory (default .)')
    parser.add_argument('disk', help='NTFS partition (e.g. /dev/disk*, \\\\.\\Harddisk*Partition*)')
    return parser.parse_args(argv)

def HDDRecovFunc(argv):
    TextReportingHDDRecov.configure(state="normal")
    args = parse_args(argv)

    f = open(args.disk, 'rb')

    if args.outdir:
        try:
            os.makedirs(args.outdir)
        except OSError:
            pass
        os.chdir(args.outdir)

    # parse essential details of the MBR
    if readat(f, 3, 8) != b'NTFS    ':
        TextReportingHDDRecov.insert(tk.END,"Not an NTFS disk???\n")
        raise ValueError("Not an NTFS disk???")

    bps, spc = struct.unpack('<HB', readat(f, 0xb, 3))
    if args.sector_size:
        bps = args.sector_size
    if args.cluster_size:
        spc = args.cluster_size
    bpc = bps * spc

    mft_clust, mftmirr_clust, clust_per_mft = struct.unpack('<QQB', readat(f, 0x30, 17))

    TextReportingHDDRecov.insert(tk.END,"Reading MFT\n")
    if args.mft:
        mftbytes = args.mft.read()
    else:
        mftbytes = read_mft(f, bpc, mft_clust, clust_per_mft)

    if args.save_mft:
        args.save_mft.write(mftbytes)

    mft = parse_mft(f, bpc, mftbytes)
    for i, file in enumerate(mft):
        try:
            fn = file['FILE_NAME'][None]()[1]
        except Exception as e:
            continue

        try:
            fullpath = '/'.join(get_filepath(mft, i))
        except Exception as e:
            fullpath = '__ORPHANED__/' + fn

        if not args.pattern:
            TextReportingHDDRecov.insert(tk.END,fullpath + "\n")
            continue

        for pat in args.pattern:
            pat = pat.lower().encode('utf8')
            if fnmatch.fnmatch(fn.lower().encode('utf8'), pat) or fnmatch.fnmatch(fullpath.lower().encode('utf8'), pat):
                TextReportingHDDRecov.insert(tk.END,"Recovering " + fullpath + "\n")
                try:
                    save_file(file, fullpath)
                except Exception as e:
                    TextReportingHDDRecov.insert(tk.END,"failed: " + str(e) + "\n")
                else:
                    TextReportingHDDRecov.insert(tk.END,"Success!\n")
    TextReportingHDDRecov.configure(state="disabled")

import tkinter as tk
from tkinter import ttk,filedialog
from Crypto.Cipher import AES
import hashlib,string,random
import wmi

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

def recoveryselecteddisk():
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
                    HDDRecovFunc(listofdisk)

def opensavetoHDDRecov():
    SaveToPath = filedialog.askdirectory()
    if SaveToPath:
        EntrySaveDiskHDDRecov.delete(0,tk.END)
        EntrySaveDiskHDDRecov.insert(0,SaveToPath)

tabHDD = tk.Frame(Ptab)
Ptab.add(tabHDD,text="HDD Reovery")
LabelTargetDiskHDDRecov = tk.Label(tabHDD,text="Target Disk: ")
LabelTargetDiskHDDRecov.grid(row=0,column=0,pady=5,sticky="W",padx=5)
EntryTargetDiskHDDRecov = ttk.Combobox(tabHDD,values=OccupiedDrivesLetter)
EntryTargetDiskHDDRecov.grid(row=0,column=1,columnspan=2,ipadx=170,sticky="E",padx=5)
LabelSaveDiskHDDRecov = tk.Label(tabHDD,text="Save to ")
LabelSaveDiskHDDRecov.grid(row=1,column=0,pady=5,sticky="W",padx=5)
EntrySaveDiskHDDRecov = tk.Entry(tabHDD)
EntrySaveDiskHDDRecov.grid(row=1,column=1,columnspan=2,ipadx=180,sticky="E",padx=5)
tk.Button(tabHDD,text="...",command=opensavetoHDDRecov).grid(row=1,column=2,ipadx=5,pady=5,sticky="E",padx=5)
TextReportingHDDRecov = tk.Text(tabHDD,height=10,width=50)
TextReportingHDDRecov.grid(row=2,column=0,columnspan=3,ipadx=80,padx=5)
TextReportingHDDRecov.configure(state="disabled")
tk.Checkbutton(tabHDD,text="Generate Report").grid(row=3,column=0,columnspan=2,sticky="W",padx=5)
tk.Button(tabHDD,text="Start Recovery",command=recoveryselecteddisk).grid(row=3,column=2,sticky="E",padx=5)

tabPartition = tk.Frame(Ptab)
Ptab.add(tabPartition,text="Partition Tools")
EntryPartition = tk.Entry(tabPartition)
EntryPartition.grid(row=0,ipadx=200,columnspan=4,pady=5,sticky="W",padx=5)
tk.Button(tabPartition,text="Dump Partition").grid(row=1,column=0,ipadx=14,sticky="W",padx=5)
LabelRenamePartition = tk.Label(tabPartition,text="Rename")
LabelRenamePartition.grid(row=1,column=1,padx=5)
EntryRenamePartition = tk.Entry(tabPartition)
EntryRenamePartition.grid(row=1,column=2,columnspan=2,ipadx=78,sticky="W",padx=5)
tk.Radiobutton(tabPartition,text="Primary Partition",value="Primary").grid(row=3,column=0,sticky="W",padx=5)
tk.Radiobutton(tabPartition,text="Extended Partition",value="Extended").grid(row=3,column=1,sticky="W",padx=5)
LabelSizePartition = tk.Label(tabPartition,text="Size(in MB): ")
LabelSizePartition.grid(row=4,column=0,sticky="W",padx=5,pady=5)
EntrySizePartition = tk.Entry(tabPartition)
EntrySizePartition.grid(row=4,column=0,columnspan=2,ipadx=25,sticky="E",padx=5,pady=5)
LabelPartitionLetter = tk.Label(tabPartition,text="Partition Letter: ")
LabelPartitionLetter.grid(row=4,column=2,sticky="W",padx=5,pady=5)
EntryPartitionLetter = ttk.Combobox(tabPartition,values=AvailableDrivesLetter)
EntryPartitionLetter.grid(row=4,column=2,columnspan=2,ipadx=25,sticky="E",padx=5,pady=5)
tk.Checkbutton(tabPartition,text="Generate Report").grid(row=5,column=0,padx=5)
tk.Button(tabPartition,text="Execute").grid(row=5,column=3,sticky="E",padx=5)

def FormattingDisk():
    TextReportingDiskFormat.configure(state="normal")
    DirectoryPath = EntryTargetDiskFormat.get()
    DirName = []
    FilesName = []
    for Dirpath, Dirname, Filesname in os.walk(DirectoryPath):
        if Dirname == []:
            for EveryFiles in Filesname:
                FilesName.append(Dirpath + "\\" + EveryFiles)
        else:
            for EveryDir in Dirname:
                DirName.insert(0,Dirpath + "\\" + EveryDir)
    RaiseErrorWhenFormat = 0
    for EverySingleFile in FilesName:
        TextReportingDiskFormat.insert(tk.END,"Deleting " + EverySingleFile + "\n")
        os.remove(EverySingleFile)
    for EverySingleDir in DirName:
        if EverySingleDir != DirectoryPath + '\\System Volume Information':
            try:
                os.rmdir(EverySingleDir)
                TextReportingDiskFormat.insert(tk.END,"Deleting " + EverySingleDir + "\n")
            except:
                RaiseErrorWhenFormat = 1
                TextReportingDiskFormat.insert(tk.END,EverySingleDir + " is not empty dir, skipping it\n")
                continue
    if RaiseErrorWhenFormat == 1:
        TextReportingDiskFormat.insert(tk.END,"If [Directory/Folder] is not empty dir happen, trying to use format once again\n")

tabFormat = tk.Frame(Ptab)
Ptab.add(tabFormat,text="Format")
LabelTargetDiskFormat = tk.Label(tabFormat,text="Target Disk/Partition: ")
LabelTargetDiskFormat.grid(row=0,column=0,pady=5,padx=5,sticky="W")
EntryTargetDiskFormat = ttk.Combobox(tabFormat,values=OccupiedDrivesLetter)
EntryTargetDiskFormat.grid(row=0,column=1,columnspan=2,ipadx=150,sticky="E",padx=5)
TextReportingDiskFormat = tk.Text(tabFormat,height=10,width=50)
TextReportingDiskFormat.grid(row=1,column=0,columnspan=3,ipadx=80,padx=5)
TextReportingDiskFormat.configure(state="disabled")
tk.Checkbutton(tabFormat,text="Generate Report").grid(row=2,column=0,padx=5)
tk.Button(tabFormat,text="Start Format",command=FormattingDisk).grid(row=2,column=2,sticky="E",padx=5)
LabelWarningFormat = tk.Label(tabFormat,text="THIS\'LL DELETE ALL FILES AND FOLDER WITHOUT EXCEPTION")
LabelWarningFormat.grid(row=3,column=0,columnspan=3,padx=5)
LabelWarningFormat1 = tk.Label(tabFormat,text=" DON\'T USE IT ON DISK CONTAIN OPERATING SYSTEM!")
LabelWarningFormat1.grid(row=4,column=0,columnspan=3,padx=5)

EncDecType = ['AES','RSA']

def openfileEnc():
    EncFile = filedialog.askopenfile(parent=tabEnc,mode="rb")
    if EncFile:
        EntryTargetDataEnc.insert(0,tk.END)
        EntryTargetDataEnc.insert(0,EncFile.name)

def openfolderenc():
    EncFolder = filedialog.askdirectory()
    if EncFolder:
        EntrySaveEncFile.insert(0,tk.END)
        EntrySaveEncFile.insert(0,EncFolder)

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
LabelTargetDataEnc.grid(row=0,column=0,pady=5,sticky="W",padx=5)
EntryTargetDataEnc = tk.Entry(tabEnc)
EntryTargetDataEnc.grid(row=0,column=1,columnspan=2,ipadx=144,pady=5,sticky="E",padx=5)
tk.Button(tabEnc,text="...",command=openfileEnc).grid(row=0,column=2,ipadx=5,pady=5,sticky="E",padx=5)
LabelEncType = tk.Label(tabEnc,text="Encrytption Type: ")
LabelEncType.grid(row=1,column=0,sticky="W",padx=5)
EntryEncType = ttk.Combobox(tabEnc,values=EncDecType)
EntryEncType.grid(row=1,column=1,columnspan=2,ipadx=135,sticky="E",padx=5)
LabelSaveEncFile = tk.Label(tabEnc,text="Save to ")
LabelSaveEncFile.grid(row=2,column=0,pady=5,sticky="W",padx=5)
EntrySaveEncFile = tk.Entry(tabEnc)
EntrySaveEncFile.grid(row=2,column=1,columnspan=2,ipadx=144,pady=5,sticky="E",padx=5)
tk.Button(tabEnc,text="...",command=openfolderenc).grid(row=2,column=2,ipadx=5,pady=5,sticky="E",padx=5)
tk.Checkbutton(tabEnc,text="Generate Report").grid(row=3,column=0,pady=5,padx=5)
tk.Button(tabEnc,text="Encrypt").grid(row=3,column=2,pady=5,sticky="E",padx=5)

def openfileDec():
    DecFile = filedialog.askopenfile(parent=tabDec,mode="rb")
    if DecFile:
        EntryTargetDataDec.delete(0,tk.END)
        EntryTargetDataDec.insert(0,DecFile.name)

def openfolderdec():
    DecFolder = filedialog.askdirectory()
    if DecFolder:
        EntrySaveDecFile.insert(0,tk.END)
        EntrySaveDecFile.insert(0,DecFolder)


tabDec = tk.Frame(Ptab)
Ptab.add(tabDec,text="Decryption")
LabelTargetDataDec = tk.Label(tabDec,text="Target Data: ")
LabelTargetDataDec.grid(row=0,column=0,pady=5,sticky="W",padx=5)
EntryTargetDataDec = tk.Entry(tabDec)
EntryTargetDataDec.grid(row=0,column=1,columnspan=2,ipadx=144,pady=5,sticky="E",padx=5)
tk.Button(tabDec,text="...",command=openfileDec).grid(row=0,column=2,ipadx=5,pady=5,sticky="E",padx=5)
LabelDecType = tk.Label(tabDec,text="Decrytption Type: ")
LabelDecType.grid(row=1,column=0,sticky="W",padx=5)
EntryDecType = ttk.Combobox(tabDec,values=EncDecType)
EntryDecType.grid(row=1,column=1,columnspan=2,ipadx=135,sticky="E",padx=5)
LabelSaveDecFile = tk.Label(tabDec,text="Save to ")
LabelSaveDecFile.grid(row=2,column=0,pady=5,sticky="W",padx=5)
EntrySaveDecFile = tk.Entry(tabDec)
EntrySaveDecFile.grid(row=2,column=1,columnspan=2,ipadx=144,pady=5,sticky="E",padx=5)
tk.Button(tabDec,text="...",command=openfolderdec).grid(row=2,column=2,ipadx=5,pady=5,sticky="E",padx=5)
tk.Checkbutton(tabDec,text="Generate Report").grid(row=3,column=0,pady=5,padx=5)
tk.Button(tabDec,text="Decrypt").grid(row=3,column=2,pady=5,sticky="E",padx=5)

Ptab.pack(expand=1,fill="both")

window.mainloop() 
