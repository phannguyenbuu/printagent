import os
from datetime import datetime, timezone
from config import ServerConfig
from db import create_session_factory
from models import (
    Base, Workspace, Location, RepairRequest, Material, 
    UserAccount, LanSite, AgentNode, Printer, Task, TaskStatus, TaskPriority, Lead
)

def seed():
    cfg = ServerConfig()
    session_factory = create_session_factory(cfg)
    session = session_factory()

    # 0. Leads
    leads_data = [
        { "id": 'default', "name": 'Default Lead', "email": 'admin@goxprint.vn', "phone": '0901234567', "notes": 'Hệ thống mặc định' },
        { "id": 'hoaphat', "name": 'Hòa Phát Group', "email": 'contact@hoaphat.com.vn', "phone": '0243-123-456', "notes": 'Khách hàng chiến lược' },
    ]
    for d in leads_data:
        if not session.get(Lead, d["id"]):
            session.add(Lead(**d))
    session.flush()

    # 1. Workspaces
    workspaces_data = [
        { "id": 'ws-1', "name": 'Công ty TNHH Gox Print', "logo": '🏭', "color": '#2196F3', "address": '123 Nguyễn Huệ, Q1, TP.HCM' },
        { "id": 'ws-2', "name": 'Công ty CP Kỹ thuật Việt Nam', "logo": '🔧', "color": '#FF9800', "address": '456 Lê Lợi, Q3, TP.HCM' },
        { "id": 'ws-3', "name": 'Nhà máy Thép Hòa Phát', "logo": '🏗️', "color": '#4CAF50', "address": '789 Quốc lộ 5, Hải Dương' },
        { "id": 'ws-4', "name": 'Tập đoàn Vật tư Phương Nam', "logo": '📦', "color": '#9C27B0', "address": '12 Đinh Tiên Hoàng, Q1, TP.HCM' },
        { "id": 'ws-5', "name": 'Công ty Điện tử Sài Gòn Tech', "logo": '💡', "color": '#E91E63', "address": '88 Nguyễn Thị Minh Khai, Q3, TP.HCM' },
    ]
    for d in workspaces_data:
        existing = session.get(Workspace, d["id"])
        if not existing:
            session.add(Workspace(**d))
        else:
            existing.name = d["name"]
            existing.address = d["address"]
    session.flush()

    # 2. Users
    users_data = [
        { "username": "supplier1", "full_name": "Nguyễn Văn An", "email": "supplier1@goxprint.vn", "role": "supplier", "lead": "default" },
        { "username": "supplier2", "full_name": "Trần Thị Bình", "email": "supplier2@goxprint.vn", "role": "supplier", "lead": "default" },
        { "username": "supplier3", "full_name": "Hoàng Thị Mai", "email": "supplier3@phuongnam.vn", "role": "supplier", "lead": "default" },
        { "username": "tech1", "full_name": "Lê Minh Cường", "email": "tech1@kythuat.vn", "role": "technician", "lead": "default" },
        { "username": "tech2", "full_name": "Phạm Đức Dũng", "email": "tech2@kythuat.vn", "role": "technician", "lead": "default" },
    ]
    user_map = {}
    for d in users_data:
        existing = session.query(UserAccount).filter_by(username=d["username"], lead=d["lead"]).first()
        if not existing:
            u = UserAccount(**d)
            session.add(u)
            session.flush()
            user_map[d["username"]] = u
        else:
            existing.email = d["email"]
            existing.full_name = d["full_name"]
            existing.role = d["role"]
            user_map[d["username"]] = existing
    session.commit()

    # 3. Tasks (Repair Requests data mapped to Task model)
    repairs_mock = [
        { "id": "req-1", "machineName": 'Máy CNC Fanuc #3', "priority": 'high', "status": 'new', "createdBy": 'supplier1', "title": "Kiểm tra trục chính" },
        { "id": "req-2", "machineName": 'Máy ép nhựa Haitian #7', "priority": 'critical', "status": 'accepted', "createdBy": 'supplier1', "assignedTo": 'tech2', "title": "Rò rỉ dầu thủy lực" },
        { "id": "req-3", "machineName": 'Robot hàn ABB IRB 1600', "priority": 'medium', "status": 'in_progress', "createdBy": 'supplier2', "assignedTo": 'tech1', "title": "Lệch tọa độ robot" },
        { "id": "req-4", "machineName": 'Máy tiện CNC Doosan #2', "priority": 'high', "status": 'completed', "createdBy": 'supplier1', "assignedTo": 'tech1', "title": "Thay vòng bi trục chính" },
    ]
    
    for r in repairs_mock:
        task_key = f"MOCK-{r['id']}"
        existing = session.query(Task).filter_by(task_key=task_key, lead="default").first()
        if not existing:
            reporter = user_map.get(r.get("createdBy"))
            assignee = user_map.get(r.get("assignedTo"))
            
            s_map = { "new": "backlog", "accepted": "todo", "in_progress": "in_progress", "completed": "done", "cancelled": "canceled" }
            
            t = Task(
                lead="default",
                task_key=task_key,
                machine_name=r["machineName"],
                title=r.get("title") or r["machineName"],
                status=s_map.get(r["status"], "backlog"),
                priority=r["priority"],
                reporter_id=reporter.id if reporter else None,
                assignee_id=assignee.id if assignee else None,
                created_at=datetime.now(timezone.utc)
            )
            session.add(t)
    
    session.commit()
    session.close()
    print("Seed finished!")

if __name__ == "__main__":
    seed()
