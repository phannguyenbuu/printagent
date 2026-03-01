import paramiko
import os

def deploy_nginx_config():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    local_conf_path = "nginx/sites-available/agentapi.quanlymay.com"
    remote_conf_path = "/etc/nginx/sites-available/agentapi.quanlymay.com.conf"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Upload the file
    sftp = ssh.open_sftp()
    print(f"Uploading {local_conf_path} to {remote_conf_path}...")
    sftp.put(local_conf_path, remote_conf_path)
    sftp.close()
    
    # Setup symlink and reload
    # Using account 34df0aed85768b9c26a83694a2a73be2 which corresponds to Choices index 1 (usually)
    # Actually, Certbot's --account flag takes the ID
    commands = [
        "ln -sf /etc/nginx/sites-available/agentapi.quanlymay.com.conf /etc/nginx/sites-enabled/agentapi.quanlymay.com.conf",
        "rm -f /etc/nginx/sites-enabled/agentapi.quanlymay.com",
        "nginx -t",
        "systemctl reload nginx",
        "certbot --nginx -d agentapi.quanlymay.com --non-interactive --agree-tos -m phannguyenbuu@gmail.com --account 34df0aed85768b9c26a83694a2a73be2"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        if out: print(out)
        if err: print(err)
        
    ssh.close()

if __name__ == "__main__":
    deploy_nginx_config()
