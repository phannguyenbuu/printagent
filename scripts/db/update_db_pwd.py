import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('31.97.76.62', username='root', password='@baoLong0511', timeout=5)
stmt = "UPDATE \\\"UserAccount\\\" SET password = 'password123' WHERE email IN ('supplier1@goxprint.vn', 'supplier3@phuongnam.vn', 'tech1@kythuat.vn', 'supplier2@goxprint.vn', 'tech2@kythuat.vn');"
stdin, stdout, stderr = client.exec_command(f'PGPASSWORD="myPass" psql -h localhost -U postgres -d GoPrinx -c "{stmt}"')
print("STDOUT:", stdout.read().decode())
print("STDERR:", stderr.read().decode())
