#!/usr/bin/env python3
"""
Flask App - Upload file và quản lý FTP server tự động
"""
import os
import socket
import threading
import logging
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from ftp_manager import create_ftp_folder, delete_ftp, FTP_ROOT

app = Flask(__name__)
app.secret_key = 'scangox-secret-key-2026'

SCAN_UPLOAD_URL = os.getenv('SCAN_UPLOAD_URL', 'https://app.goxprint.com/api/polling/scan-upload')
SCAN_UPLOAD_TIMEOUT = int(os.getenv('SCAN_UPLOAD_TIMEOUT', '60'))

# Cấu hình log
LOG_FILE = r"C:\scangox\ftp_server.log"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Global state
FTP_SERVER_INFO = {
    'port': None,
    'user_id': None,
    'folder': None,
    'email': 'phannguyenbuu@gmail.com',
    'running': False,
    'server': None
}


def is_port_available(port):
    """Kiểm tra port có khả dụng không"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            return True
    except OSError:
        return False


def start_ftp_server(start_port=2121, max_attempts=10):
    """
    Khởi động FTP server, tự động tăng port nếu bận
    """
    email = FTP_SERVER_INFO['email']
    user_id, folder_path = create_ftp_folder(email)
    
    FTP_SERVER_INFO['user_id'] = user_id
    FTP_SERVER_INFO['folder'] = folder_path
    
    logging.info(f"Tạo FTP folder cho {email}: {folder_path} (ID: {user_id})")
    
    # Tìm port khả dụng
    port = start_port
    for attempt in range(max_attempts):
        if is_port_available(port):
            logging.info(f"Port {port} khả dụng, đang khởi động FTP server...")
            break
        else:
            logging.warning(f"Port {port} đã bận, thử port tiếp theo...")
            port += 1
    else:
        logging.error(f"Không tìm thấy port khả dụng sau {max_attempts} lần thử")
        return
    
    # Cấu hình FTP server
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(FTP_ROOT, perm='elradfmw')
    
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = f"ScanGoX FTP Server - ID: {user_id}"
    
    # Khởi động server
    try:
        server = FTPServer(('0.0.0.0', port), handler)
        FTP_SERVER_INFO['port'] = port
        FTP_SERVER_INFO['running'] = True
        FTP_SERVER_INFO['server'] = server
        
        logging.info(f"FTP Server đang chạy trên port {port}")
        logging.info(f"Thư mục gốc: {FTP_ROOT}")
        logging.info(f"User folder: {folder_path}")
        
        server.serve_forever()
    except Exception as e:
        logging.error(f"Lỗi khởi động FTP server: {e}")
        FTP_SERVER_INFO['running'] = False


@app.route('/')
def index():
    """Trang chủ với form upload"""
    return render_template('index.html', info=FTP_SERVER_INFO)


@app.route('/upload', methods=['POST'])
def upload_file():
    """Xử lý upload file"""
    if 'file' not in request.files:
        flash('Không có file nào được chọn', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Không có file nào được chọn', 'error')
        return redirect(url_for('index'))
    
    # Lưu file vào thư mục FTP
    if FTP_SERVER_INFO['folder']:
        filepath = os.path.join(FTP_SERVER_INFO['folder'], file.filename)
        file.save(filepath)
        logging.info(f"File uploaded: {file.filename} -> {filepath}")

        sync_ok = False
        try:
            with open(filepath, 'rb') as file_handle:
                files = {
                    'file': (file.filename, file_handle, 'application/octet-stream')
                }
                data = {
                    'lead': 'default',
                    'lan_uid': 'scanner-gox',
                    'agent_uid': FTP_SERVER_INFO.get('user_id') or 'scanner-local',
                    'hostname': socket.gethostname(),
                    'local_ip': request.remote_addr or '',
                    'source_path': filepath,
                    'source_root': FTP_ROOT,
                    'source_root_label': 'scangox',
                    'source_relative_path': os.path.basename(filepath),
                    'fingerprint': 'scanner-gox-' + (FTP_SERVER_INFO.get('user_id') or 'na'),
                    'timestamp': datetime.now().astimezone().isoformat(),
                }
                response = requests.post(
                    SCAN_UPLOAD_URL,
                    data=data,
                    files=files,
                    timeout=SCAN_UPLOAD_TIMEOUT,
                )
                sync_ok = response.ok
                if response.ok:
                    logging.info('Dong bo VPS thanh cong: %s -> %s', filepath, SCAN_UPLOAD_URL)
                else:
                    logging.error(
                        'Dong bo VPS loi HTTP %s: %s',
                        response.status_code,
                        response.text[:400],
                    )
        except Exception as exc:
            logging.exception('Dong bo VPS that bai cho file %s: %s', filepath, exc)

        if sync_ok:
            flash(f'Upload + dong bo VPS thanh cong: {file.filename}', 'success')
        else:
            flash(f'Upload local thanh cong nhung dong bo VPS loi: {file.filename}', 'error')
    else:
        flash('FTP server chưa sẵn sàng', 'error')
    
    return redirect(url_for('index'))


@app.route('/stop-ftp', methods=['POST'])
def stop_ftp():
    """Tắt FTP server"""
    if FTP_SERVER_INFO['running'] and FTP_SERVER_INFO['server']:
        try:
            FTP_SERVER_INFO['server'].close_all()
            FTP_SERVER_INFO['running'] = False
            FTP_SERVER_INFO['port'] = None
            logging.info("FTP Server đã tắt")
            flash('FTP Server đã tắt', 'success')
        except Exception as e:
            logging.error(f"Lỗi khi tắt FTP server: {e}")
            flash(f'Lỗi: {e}', 'error')
    else:
        flash('FTP Server không đang chạy', 'error')
    
    return redirect(url_for('index'))


@app.route('/delete-ftp', methods=['POST'])
def delete_ftp_route():
    """Xóa FTP (mapping + thư mục)"""
    email = FTP_SERVER_INFO['email']
    
    # Tắt server trước nếu đang chạy
    if FTP_SERVER_INFO['running'] and FTP_SERVER_INFO['server']:
        try:
            FTP_SERVER_INFO['server'].close_all()
            FTP_SERVER_INFO['running'] = False
        except:
            pass
    
    # Xóa mapping và thư mục
    keep_folder = request.form.get('keep_folder') == 'true'
    success = delete_ftp(email, keep_folder=keep_folder)
    
    if success:
        FTP_SERVER_INFO['user_id'] = None
        FTP_SERVER_INFO['folder'] = None
        FTP_SERVER_INFO['port'] = None
        msg = 'Đã xóa FTP (giữ thư mục)' if keep_folder else 'Đã xóa FTP và thư mục'
        flash(msg, 'success')
    else:
        flash('Không tìm thấy FTP để xóa', 'error')
    
    return redirect(url_for('index'))


@app.route('/status')
def status():
    """API trả về trạng thái FTP server"""
    return jsonify({
        'port': FTP_SERVER_INFO['port'],
        'user_id': FTP_SERVER_INFO['user_id'],
        'folder': FTP_SERVER_INFO['folder'],
        'email': FTP_SERVER_INFO['email'],
        'running': FTP_SERVER_INFO['running']
    })


if __name__ == '__main__':
    # Khởi động FTP server trong thread riêng
    ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
    ftp_thread.start()
    
    # Đợi FTP server khởi động
    import time
    time.sleep(2)
    
    # Khởi động Flask
    logging.info("Khởi động Flask web server trên http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

