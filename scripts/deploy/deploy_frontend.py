import os
import paramiko
from stat import S_ISDIR

def deploy():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('31.97.76.62', username='root', password='@baoLong0511', timeout=5)
    sftp = client.open_sftp()
    
    remote_dir = '/var/www/app-gox'
    local_dir = 'app-gox/dist'
    
    # Upload files recursively
    for root, dirs, files in os.walk(local_dir):
        for fname in files:
            local_path = os.path.join(root, fname)
            rel_path = os.path.relpath(local_path, local_dir).replace('\\', '/')
            remote_path = f"{remote_dir}/{rel_path}"
            
            # Ensure remote directory exists
            remote_parent = os.path.dirname(remote_path)
            try:
                sftp.stat(remote_parent)
            except IOError:
                # Create missing directories
                parts = remote_parent.split('/')
                path = ''
                for part in parts:
                    if not part: continue
                    path += f'/{part}'
                    try:
                        sftp.stat(path)
                    except IOError:
                        sftp.mkdir(path)
            
            sftp.put(local_path, remote_path)
            
    sftp.close()
    
    # Fix ownership
    client.exec_command(f'chown -R www-data:www-data {remote_dir}')
    client.close()
    print("Deployment to VPS successful!")

if __name__ == '__main__':
    deploy()
