import paramiko
import json

def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("agentapi.quanlymay.com", username="root", password="@baoLong0511")
    
    # Query ftp_sites for agent_uid = 'kythuat02' in GoPrinx database
    cmd = 'PGPASSWORD="@baoLong0511" psql -U postgres -d GoPrinx -c "SELECT agent_uid, ftp_sites FROM \\"AgentNode\\" WHERE agent_uid = \'kythuat02\';"'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    print(stdout.read().decode('utf-8'))
    print(stderr.read().decode('utf-8'))
    ssh.close()

if __name__ == '__main__':
    main()
