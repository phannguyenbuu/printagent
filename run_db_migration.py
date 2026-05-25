import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

# Use a clean shell script on remote to run python script
remote_py = """
import psycopg2
conn = psycopg2.connect('postgresql://postgres:myPass@localhost:5432/GoPrinx')
cur = conn.cursor()
cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='LanSite'")
cols = [r[0] for r in cur.fetchall()]
print('Existing cols:', cols)
if 'address' not in cols:
    cur.execute('ALTER TABLE "LanSite" ADD COLUMN "address" VARCHAR(255) DEFAULT \\'\\'')
    conn.commit()
    print('Added address column!')
else:
    print('address column already exists!')
conn.close()
"""

# Write remote python file
sftp = ssh.open_sftp()
with sftp.file('/tmp/db_migration.py', 'w') as f:
    f.write(remote_py)
sftp.close()

# Execute it
_, out, err = ssh.exec_command('/opt/printagent/venv/bin/python3 /tmp/db_migration.py')
print('STDOUT:', out.read().decode('utf-8'))
print('STDERR:', err.read().decode('utf-8'))

ssh.close()
