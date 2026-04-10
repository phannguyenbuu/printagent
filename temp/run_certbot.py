import paramiko
import sys

def run_certbot():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    domain = "agentapi.quanlymay.com"
    # Use the full ID found in the directory
    account_id = "b7dcd76309abe8152e645f9171dccddc" 
    cmd = f"certbot --nginx -d {domain} --non-interactive --agree-tos --account {account_id}"
    
    print(f"Executing: {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    
    output = stdout.read().decode('utf-8', errors='ignore')
    error = stderr.read().decode('utf-8', errors='ignore')
    
    if output:
        print("Output:")
        print(output)
    if error:
        print("Error/Log:")
        print(error)
        
    ssh.close()

if __name__ == "__main__":
    run_certbot()
