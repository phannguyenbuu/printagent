from __future__ import annotations
import json
from datetime import datetime, timezone
from sqlalchemy import select, delete
from db import create_session_factory
from config import ServerConfig
from models import (
    UserAccount,
    NetworkInfo,
    Task
)

def seed():
    config = ServerConfig()
    session_factory = create_session_factory(config)
    
    with session_factory() as session:
        # 1. Clear existing sample data to avoid duplicates
        session.execute(delete(Task))
        session.execute(delete(UserAccount))
        session.execute(delete(NetworkInfo))
        session.commit()

        # 2. Seed Users
        users_data = [
            {"username": "supplier1", "full_name": "Nguyễn Văn An", "email": "supplier1@goxprint.vn", "role": "admin", "phone": "0901-111-222"},
            {"username": "supplier2", "full_name": "Trần Thị Bình", "email": "supplier2@goxprint.vn", "role": "admin", "phone": "0901-333-444"},
            {"username": "supplier3", "full_name": "Hoàng Thị Mai", "email": "supplier3@phuongnam.vn", "role": "admin", "phone": "0908-999-111"},
            {"username": "tech1", "full_name": "Lê Minh Cường", "email": "tech1@kythuat.vn", "role": "worker", "phone": "0912-555-666"},
            {"username": "tech2", "full_name": "Phạm Đức Dũng", "email": "tech2@kythuat.vn", "role": "worker", "phone": "0912-777-888"},
        ]
        
        user_map = {}
        for u in users_data:
            user = UserAccount(
                lead="default",
                username=u["username"],
                full_name=u["full_name"],
                email=u["email"],
                phone_number=u["phone"],
                role=u["role"],
                is_active=True
            )
            session.add(user)
            session.flush() # Get ID
            user_map[u["username"]] = user.id

        # 3. Seed Companies (NetworkInfo)
        networks_data = [
            {"name": "Công ty TNHH Gox Print", "addr": "123 Nguyễn Huệ, Q1, TP.HCM", "uid": "ws-1"},
            {"name": "Công ty CP Kỹ thuật Việt Nam", "addr": "456 Lê Lợi, Q3, TP.HCM", "uid": "ws-2"},
            {"name": "Nhà máy Thép Hòa Phát", "addr": "789 Quốc lộ 5, Hải Dương", "uid": "ws-3"},
            {"name": "Tập đoàn Vật tư Phương Nam", "addr": "12 Đinh Tiên Hoàng, Q1, TP.HCM", "uid": "ws-4"},
            {"name": "Công ty Điện tử Sài Gòn Tech", "addr": "88 Nguyễn Thị Minh Khai, Q3, TP.HCM", "uid": "ws-5"},
        ]
        
        for n in networks_data:
            net = NetworkInfo(
                lead="default",
                lan_uid=n["uid"],
                network_name=n["name"],
                office_name=n["name"],
                real_address=n["addr"]
            )
            session.add(net)

        # 4. Seed Tasks
        tasks_data = [
            {"machine": "Máy CNC Fanuc #3", "title": "Kiểm tra trục chính", "priority": "high", "status": "pending", "user": "supplier1"},
            {"machine": "Máy ép nhựa Haitian #7", "title": "Rò rỉ thủy lực", "priority": "urgent", "status": "assigned", "user": "supplier2"},
            {"machine": "Robot hàn ABB IRB 1600", "title": "Calibrate tọa độ", "priority": "medium", "status": "in_progress", "user": "supplier2"},
            {"machine": "Máy tiện CNC Doosan #2", "title": "Thay vòng bi trục chính", "priority": "high", "status": "completed", "user": "supplier1"},
            {"machine": "Máy phay Mazak #5", "title": "Đứt dây curoa", "priority": "urgent", "status": "completed", "user": "supplier1"},
        ]
        
        for t in tasks_data:
            task = Task(
                lead="default",
                title=t["title"],
                machine_name=t["machine"],
                priority=t["priority"],
                status=t["status"],
                reporter_id=user_map.get(t["user"]),
                description=f"Sample task for {t['machine']}"
            )
            session.add(task)

        session.commit()
        print("Data seeded successfully!")

if __name__ == "__main__":
    seed()
