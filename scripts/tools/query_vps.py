import paramiko

HOSTNAME = "agentapi.quanlymay.com"
USERNAME = "root"
PASSWORD = "@baoLong0511"

def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOSTNAME, username=USERNAME, password=PASSWORD)
    
    cmd = 'cd /opt/printagent && venv/bin/python3 -c "from models import Printer; from sqlalchemy import create_engine; from sqlalchemy.orm import sessionmaker; engine = create_engine(\'postgresql://printagent:gox918721@localhost:5432/printagent\'); Session = sessionmaker(bind=engine); print([(p.printer_name, p.ip, p.lan_uid) for p in Session().query(Printer).all()])"'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    
    print("OUT:")
    print(out)
    print("ERR:")
    print(err)
    ssh.close()

if __name__ == "__main__":
    main()
