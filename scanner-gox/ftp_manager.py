#!/usr/bin/env python3
"""
FTP Manager - Quản lý ID và thư mục FTP cho scanner
Tạo ID 6 ký tự từ email (bắt đầu bằng chữ), lưu mapping, tạo thư mục tự động
"""
import base64
import json
import os
import shutil
from pathlib import Path

MAPPING_FILE = r"C:\scangox\mapping.json"
FTP_ROOT = r"C:\scangox"


def email_to_id(email: str) -> str:
    """
    Chuyển email thành ID 6 ký tự, bắt đầu bằng chữ cái
    Dùng Base64 URL-safe, ổn định và có thể decode
    """
    encoded = base64.urlsafe_b64encode(email.encode('utf-8')).decode('ascii')
    # Bỏ padding '=' và lấy 5 ký tự đầu, thêm 'a' vào đầu
    safe_id = 'a' + encoded.rstrip('=')[:5]
    return safe_id


def load_mapping() -> dict:
    """Đọc mapping từ file JSON"""
    if not os.path.exists(MAPPING_FILE):
        return {}
    try:
        with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Lỗi đọc mapping: {e}")
        return {}


def save_mapping(mapping: dict):
    """Lưu mapping vào file JSON"""
    os.makedirs(os.path.dirname(MAPPING_FILE), exist_ok=True)
    with open(MAPPING_FILE, 'w', encoding='utf-8') as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)


def get_email_from_id(user_id: str) -> str:
    """Dịch ngược ID về email từ mapping"""
    mapping = load_mapping()
    return mapping.get(user_id, None)


def create_ftp_folder(email: str) -> tuple:
    """
    Tạo thư mục FTP cho email
    Trả về (id, đường_dẫn_thư_mục)
    """
    user_id = email_to_id(email)
    
    # Cập nhật mapping
    mapping = load_mapping()
    mapping[user_id] = email
    save_mapping(mapping)
    
    # Tạo thư mục
    folder_path = os.path.join(FTP_ROOT, user_id)
    os.makedirs(folder_path, exist_ok=True)
    
    return user_id, folder_path


def delete_ftp(email_or_id: str, keep_folder: bool = False) -> bool:
    """
    Xóa FTP account + mapping + thư mục
    
    Args:
        email_or_id: Email hoặc ID cần xóa
        keep_folder: True = giữ lại thư mục, False = xóa luôn thư mục
    
    Returns:
        True nếu xóa thành công, False nếu không tìm thấy
    """
    mapping = load_mapping()
    
    # Xác định ID
    if email_or_id in mapping:
        # Đã truyền ID
        user_id = email_or_id
        email = mapping[user_id]
    else:
        # Truyền email, cần tìm ID
        user_id = email_to_id(email_or_id)
        email = mapping.get(user_id)
        
        if not email:
            print(f"Không tìm thấy mapping cho: {email_or_id}")
            return False
    
    # Xóa khỏi mapping
    del mapping[user_id]
    save_mapping(mapping)
    print(f"Đã xóa mapping: {user_id} -> {email}")
    
    # Xóa thư mục nếu cần
    folder_path = os.path.join(FTP_ROOT, user_id)
    if os.path.exists(folder_path):
        if keep_folder:
            print(f"Giữ lại thư mục: {folder_path}")
        else:
            shutil.rmtree(folder_path)
            print(f"Đã xóa thư mục: {folder_path}")
    
    return True


def main():
    """Demo: tạo và xóa thư mục FTP"""
    test_email = "phannguyenbuu@gmail.com"
    
    print("=== TẠO FTP ===")
    print(f"Email: {test_email}")
    user_id, folder_path = create_ftp_folder(test_email)
    
    print(f"ID: {user_id}")
    print(f"Thư mục: {folder_path}")
    print(f"Mapping đã lưu tại: {MAPPING_FILE}")
    
    # Kiểm tra decode
    decoded_email = get_email_from_id(user_id)
    print(f"\nKiểm tra decode: {user_id} -> {decoded_email}")
    print(f"Khớp: {decoded_email == test_email}")
    
    # Demo xóa (comment lại để không tự xóa khi chạy)
    # print("\n=== XÓA FTP ===")
    # delete_ftp(test_email, keep_folder=False)


if __name__ == "__main__":
    main()
