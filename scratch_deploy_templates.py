import paramiko

def deploy():
    print("Connecting to VPS 31.97.76.62...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

    sftp = ssh.open_sftp()
    
    local = 'backend/templates/agents.html'
    remote = '/opt/printagent/templates/agents.html'
    
    print(f"Uploading {local} to {remote}...")
    sftp.put(local, remote)
    print("Upload successful!")
        
    sftp.close()
    
    print("Restarting printagent service on VPS...")
    stdin, stdout, stderr = ssh.exec_command('systemctl restart printagent')
    print("Service restarted successfully!")
    ssh.close()

if __name__ == '__main__':
    deploy()
