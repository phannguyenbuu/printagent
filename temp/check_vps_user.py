import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('31.97.76.62', username='root', password='@baoLong0511')
stdin, stdout, stderr = client.exec_command('ls -ld /var/www/app-gox && ls -l /var/www/app-gox')
print(stdout.read().decode())
