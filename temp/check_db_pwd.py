import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('31.97.76.62', username='root', password='@baoLong0511', timeout=5)
# Using double quotes for table name because it is camel case
stdin, stdout, stderr = client.exec_command('PGPASSWORD="myPass" psql -h localhost -U postgres -d GoPrinx -c "SELECT email, password FROM \\"UserAccount\\";"')
print("STDOUT:", stdout.read().decode())
print("STDERR:", stderr.read().decode())
