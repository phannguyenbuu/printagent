import ftplib

try:
    print("Connecting to 192.168.1.12 on port 2131...")
    ftp = ftplib.FTP()
    ftp.connect("192.168.1.12", 2131, timeout=5)
    print("Connected successfully! Logging in...")
    ftp.login("goxprint", "gox918721")
    print("Login success! FTP Features:")
    print(ftp.getwelcome())
    print("Directory listing:")
    print(ftp.nlst())
    ftp.quit()
    print("FTP Test Passed OK!")
except Exception as exc:
    print("FTP Test Failed:", exc)
