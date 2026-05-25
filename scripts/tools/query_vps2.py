import paramiko

HOSTNAME = "agentapi.quanlymay.com"
USERNAME = "root"
PASSWORD = "@baoLong0511"

def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOSTNAME, username=USERNAME, password=PASSWORD)
    
    cmd = 'sudo -u postgres psql -d GoPrinx -c "SELECT id, email, email_type, pc_name FROM \\"LanEmail\\" WHERE email = \'sang@gmail.com\';"'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    print("OUT:")
    print(stdout.read().decode())
    print("ERR:")
    print(stderr.read().decode())
    ssh.close()

if __name__ == "__main__":
    main()
