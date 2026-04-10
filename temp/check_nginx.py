import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('31.97.76.62', username='root', password='@baoLong0511', timeout=5)
stdin, stdout, stderr = client.exec_command('cat /etc/nginx/sites-available/agentapi.quanlymay.com')
print("STDOUT:", stdout.read().decode())
print("STDERR:", stderr.read().decode())
