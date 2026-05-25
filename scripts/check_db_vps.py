import paramiko

def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("agentapi.quanlymay.com", username="root", password="@baoLong0511")
    
    # Query api via local curl on VPS
    stdin, stdout, stderr = ssh.exec_command("curl -s http://localhost:8005/api/lan-sites")
    print(stdout.read().decode('utf-8', errors='replace'))
    print(stderr.read().decode('utf-8', errors='replace'))
    ssh.close()

if __name__ == '__main__':
    main()
