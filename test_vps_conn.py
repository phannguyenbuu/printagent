import paramiko
import sys

def get_vps_info(hostname, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password, timeout=10)
        
        stdin, stdout, stderr = client.exec_command('uname -a; lsb_release -a')
        print(stdout.read().decode())
        
        client.close()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    get_vps_info("agentapi.quanlymay.com", "root", "@baoLong0511")
