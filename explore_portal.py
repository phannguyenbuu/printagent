import paramiko

def explore_portal():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Path with spaces
    target_dir = "/root/htxgo/uploads/portal/THANG 10 2024"
    
    print(f"Listing contents of: {target_dir}")
    # Use quotes around path to handle spaces
    cmd = f'ls -F "{target_dir}"'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    if output:
        print("Files found:")
        print(output)
    if error:
        print("Error:")
        print(error)
        
    ssh.close()

if __name__ == "__main__":
    explore_portal()
