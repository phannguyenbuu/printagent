import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('31.97.76.62', username='root', password='@baoLong0511', timeout=5)
sftp = client.open_sftp()
sftp.get('/opt/printagent/app.py', 'app_vps.py')
sftp.close()
client.close()
print("app.py downloaded successfully.")
