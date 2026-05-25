import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

cmd = """/opt/printagent/venv/bin/python3 -c "
import psycopg2
try:
    conn = psycopg2.connect('postgresql://postgres:myPass@localhost:5432/GoPrinx')
    cursor = conn.cursor()
    cursor.execute('SELECT lead, lan_uid, lan_name, subnet_cidr FROM \\"LanSite\\"')
    print('LanSites:', cursor.fetchall())
    cursor.execute('SELECT lead, agent_uid, lan_uid, hostname, local_ip, is_online, last_seen_at FROM \\"AgentNode\\"')
    print('Agents:', cursor.fetchall())
    conn.close()
except Exception as e:
    print('Error:', e)
" """

_, out, err = ssh.exec_command(cmd)
print("=== DB QUERY RESULTS ===")
print(out.read().decode())
print("=== DB QUERY ERRORS ===")
print(err.read().decode())

ssh.close()
