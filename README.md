# LANview
Simple LAN scanner that mixes Ping and ARP scans together

![lanview](https://github.com/user-attachments/assets/a528a3af-85d2-4daa-b6be-7088c5918551)


# Requirements #
This Python3 script requires tkinter, psutil, scapy and ping3.

**On Debian**

```apt install python3-scapy python3-psutil python3-ping3```

**On Generic Linux and Windows**

```pip install scapy psutil ping3```

# Compile #

**On Windows**

```pip install pyinstaller```

```pyinstaller.exe --onefile --windowed lanview.py --icon lanview.ico  --clean```
