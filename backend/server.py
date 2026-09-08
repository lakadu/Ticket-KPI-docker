from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import uuid
import io
import csv
import base64
import hmac
import asyncio
import logging
import httpx
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Any, Dict

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, Query
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

# ---------- Setup ----------

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("itsm")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="IT Ticketing & KPI Management System")
api = APIRouter(prefix="/api")

JWT_ALGO = "HS256"
JWT_SECRET = os.environ["JWT_SECRET"]

ROLES = ["admin", "manager", "supervisor", "technician", "customer"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
PRIORITY_WEIGHTS = {"Low": 1, "Medium": 2, "High": 3, "Critical": 5}
STATUSES = ["Open", "Assigned", "On Progress", "Pending", "Resolved", "Closed", "Reopened"]
DEFAULT_SLA = {  # minutes
    "Critical": {"response": 15, "resolution": 240},
    "High": {"response": 30, "resolution": 480},
    "Medium": {"response": 120, "resolution": 1440},
    "Low": {"response": 240, "resolution": 2880},
}
DEFAULT_KPI = {
    "weights": {
        "sla_compliance": 25,
        "productivity": 20,
        "response_time": 15,
        "resolution_time": 15,
        "reopen_rate": 10,
        "customer_rating": 10,
        "documentation": 5,
    },
    "thresholds": {"excellent": 90, "good": 80, "fair": 70},
    "productivity_target": 30,  # weighted points per period for full score
}

# ---------- Helpers ----------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    return datetime.fromisoformat(s)

def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def verify_pw(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False

def create_token(user_id: str, kind: str = "access") -> str:
    exp = datetime.now(timezone.utc) + (timedelta(minutes=60 * 12) if kind == "access" else timedelta(days=7))
    payload = {"sub": user_id, "type": kind, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def strip_user(u: Dict[str, Any]) -> Dict[str, Any]:
    u = dict(u)
    u.pop("password_hash", None)
    u.pop("_id", None)
    return u

async def get_current_user(request: Request) -> Dict[str, Any]:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        if payload.get("type") != "access":
            raise HTTPException(401, "Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]})
        if not user or not user.get("active", True):
            raise HTTPException(401, "User not found or inactive")
        return strip_user(user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

def require_roles(*allowed: str):
    async def dep(user=Depends(get_current_user)):
        if user["role"] not in allowed:
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dep

async def log_audit(user_id: str, action: str, entity: str, entity_id: str = "", meta: Dict[str, Any] = None):
    await db.audit_logs.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "meta": meta or {},
        "timestamp": now_iso(),
    })

# ---------- Models ----------

class LoginIn(BaseModel):
    identifier: str  # email or username
    password: str

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    name: str
    password: str
    role: str
    department: Optional[str] = None
    phone: Optional[str] = None

class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None

class TicketCreate(BaseModel):
    subject: str
    description: str
    category_id: Optional[str] = None
    subcategory: Optional[str] = None
    priority: str = "Medium"
    department: Optional[str] = None
    customer_id: Optional[str] = None  # optional; if not customer role
    reported_via: Optional[str] = None  # Phone | Walk-in | Email | Chat | Self-service
    attachments: List[Dict[str, Any]] = Field(default_factory=list)

class QuickCustomerCreate(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    phone: Optional[str] = None

class TicketAssign(BaseModel):
    technician_id: str  # primary/PIC
    additional: List[str] = Field(default_factory=list)  # optional co-technicians

class TicketCollaborators(BaseModel):
    technician_ids: List[str]  # add these as collaborators

class TicketStatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None

class TicketResolve(BaseModel):
    root_cause: str
    resolution: str
    technician_notes: Optional[str] = None
    documentation_complete: bool = True

class TicketRate(BaseModel):
    rating: int
    feedback: Optional[str] = None

class CategoryIn(BaseModel):
    name: str
    subcategories: List[str] = Field(default_factory=list)

class SLARulesIn(BaseModel):
    rules: Dict[str, Dict[str, int]]  # priority -> {response, resolution}

class KPIConfigIn(BaseModel):
    weights: Dict[str, float]
    thresholds: Dict[str, float]
    productivity_target: float

class SettingsIn(BaseModel):
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    whatsapp_provider: Optional[str] = None
    whatsapp_api_key: Optional[str] = None
    whatsapp_sender: Optional[str] = None

# ---------- SLA / KPI helpers ----------

async def get_sla_rules() -> Dict[str, Dict[str, int]]:
    doc = await db.settings.find_one({"key": "sla_rules"})
    return doc["value"] if doc else DEFAULT_SLA

async def get_kpi_config() -> Dict[str, Any]:
    doc = await db.settings.find_one({"key": "kpi_config"})
    return doc["value"] if doc else DEFAULT_KPI

def minutes_between(a: Optional[str], b: Optional[str]) -> Optional[float]:
    if not a or not b:
        return None
    return (parse_iso(b) - parse_iso(a)).total_seconds() / 60.0

async def compute_ticket_sla(ticket: Dict[str, Any]) -> Dict[str, Any]:
    rules = await get_sla_rules()
    prio = ticket.get("priority", "Medium")
    r = rules.get(prio, DEFAULT_SLA[prio])
    response_target = r["response"]
    resolution_target = r["resolution"]
    created = ticket.get("created_at")
    first_response = ticket.get("first_response_at") or ticket.get("assigned_at")
    resolved = ticket.get("resolved_at")

    response_time = minutes_between(created, first_response)
    resolution_time = minutes_between(created, resolved)

    now = datetime.now(timezone.utc)
    age = (now - parse_iso(created)).total_seconds() / 60.0 if created else 0

    sla_response_ok = None
    if response_time is not None:
        sla_response_ok = response_time <= response_target
    sla_resolution_ok = None
    if resolution_time is not None:
        sla_resolution_ok = resolution_time <= resolution_target

    # SLA status indicator (green/yellow/red)
    sla_status = "on_track"
    if ticket.get("status") in ("Resolved", "Closed"):
        sla_status = "met" if (sla_response_ok is not False and sla_resolution_ok is not False) else "violated"
    else:
        # not yet resolved -> compare age vs resolution target
        pct = (age / resolution_target) * 100 if resolution_target > 0 else 0
        if pct >= 100:
            sla_status = "violated"
        elif pct >= 75:
            sla_status = "warning"
        else:
            sla_status = "on_track"

    return {
        "response_target": response_target,
        "resolution_target": resolution_target,
        "response_time": response_time,
        "resolution_time": resolution_time,
        "sla_response_ok": sla_response_ok,
        "sla_resolution_ok": sla_resolution_ok,
        "sla_status": sla_status,
        "age_minutes": age,
    }

async def enrich_ticket(t: Dict[str, Any]) -> Dict[str, Any]:
    t = dict(t)
    t.pop("_id", None)
    sla = await compute_ticket_sla(t)
    t["sla"] = sla
    t["weight"] = PRIORITY_WEIGHTS.get(t.get("priority", "Medium"), 2)
    return t

# ---------- Auth ----------

def set_auth_cookies(response: Response, user_id: str):
    access = create_token(user_id, "access")
    refresh = create_token(user_id, "refresh")
    # Cookie policy — configurable supaya bekerja di HTTP local & HTTPS production
    same_site = os.environ.get("COOKIE_SAMESITE", "none").lower()  # "none" | "lax" | "strict"
    secure = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
    response.set_cookie("access_token", access, httponly=True, secure=secure, samesite=same_site, max_age=60 * 60 * 12, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=secure, samesite=same_site, max_age=60 * 60 * 24 * 7, path="/")

@api.post("/auth/login")
async def login(body: LoginIn, response: Response):
    ident = body.identifier.strip().lower()
    user = await db.users.find_one({"$or": [{"email": ident}, {"username": ident}]})
    if not user or not verify_pw(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    if not user.get("active", True):
        raise HTTPException(403, "Account disabled")
    set_auth_cookies(response, user["id"])
    await log_audit(user["id"], "login", "user", user["id"])
    return strip_user(user)

@api.post("/auth/logout")
async def logout(response: Response, user=Depends(get_current_user)):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    await log_audit(user["id"], "logout", "user", user["id"])
    return {"ok": True}

@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user

# ---------- Users ----------

@api.get("/users")
async def list_users(role: Optional[str] = None, user=Depends(get_current_user)):
    q = {}
    if role:
        q["role"] = role
    if user["role"] == "customer":
        raise HTTPException(403, "Forbidden")
    docs = await db.users.find(q).to_list(500)
    return [strip_user(d) for d in docs]

@api.post("/users")
async def create_user(body: UserCreate, user=Depends(require_roles("admin", "manager"))):
    if body.role not in ROLES:
        raise HTTPException(400, "Invalid role")
    email = body.email.lower()
    username = body.username.lower()
    if await db.users.find_one({"$or": [{"email": email}, {"username": username}]}):
        raise HTTPException(400, "Email or username exists")
    doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "username": username,
        "name": body.name,
        "role": body.role,
        "department": body.department,
        "phone": body.phone,
        "active": True,
        "password_hash": hash_pw(body.password),
        "created_at": now_iso(),
    }
    await db.users.insert_one(doc)
    await log_audit(user["id"], "create_user", "user", doc["id"], {"email": email, "role": body.role})
    return strip_user(doc)

@api.patch("/users/{uid}")
async def update_user(uid: str, body: UserUpdate, user=Depends(require_roles("admin", "manager"))):
    upd = {k: v for k, v in body.model_dump(exclude_none=True).items() if k != "password"}
    if body.password:
        upd["password_hash"] = hash_pw(body.password)
    if not upd:
        raise HTTPException(400, "No changes")
    r = await db.users.update_one({"id": uid}, {"$set": upd})
    if r.matched_count == 0:
        raise HTTPException(404, "Not found")
    await log_audit(user["id"], "update_user", "user", uid, {k: (v if k != "password_hash" else "***") for k, v in upd.items()})
    return {"ok": True}

@api.delete("/users/{uid}")
async def delete_user(uid: str, user=Depends(require_roles("admin"))):
    await db.users.update_one({"id": uid}, {"$set": {"active": False}})
    await log_audit(user["id"], "deactivate_user", "user", uid)
    return {"ok": True}

@api.post("/customers/quick")
async def quick_create_customer(body: QuickCustomerCreate, user=Depends(require_roles("admin", "manager", "supervisor", "technician"))):
    """Helpdesk-friendly: quickly create a customer while filing a ticket on their behalf.
    Generates a username from name+random suffix, sets a default password 'customer123' the customer can change later."""
    import re, secrets
    base = re.sub(r"[^a-z0-9]+", "", body.name.lower())[:12] or "cust"
    for _ in range(6):
        suffix = secrets.token_hex(2)
        username = f"{base}{suffix}"
        if not await db.users.find_one({"username": username}):
            break
    email = (body.email or f"{username}@itsm.local").lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already exists")
    doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "username": username,
        "name": body.name,
        "role": "customer",
        "department": body.department,
        "phone": body.phone,
        "active": True,
        "password_hash": hash_pw("customer123"),
        "created_at": now_iso(),
    }
    await db.users.insert_one(doc)
    await log_audit(user["id"], "quick_create_customer", "user", doc["id"], {"email": email, "created_by_role": user["role"]})
    return strip_user(doc)

# ---------- Categories ----------

@api.get("/categories")
async def list_categories(_=Depends(get_current_user)):
    docs = await db.categories.find({}, {"_id": 0}).to_list(200)
    return docs

@api.post("/categories")
async def create_category(body: CategoryIn, user=Depends(require_roles("admin", "manager"))):
    doc = {"id": str(uuid.uuid4()), "name": body.name, "subcategories": body.subcategories, "created_at": now_iso()}
    await db.categories.insert_one(doc)
    doc.pop("_id", None)
    await log_audit(user["id"], "create_category", "category", doc["id"])
    return doc

@api.patch("/categories/{cid}")
async def update_category(cid: str, body: CategoryIn, user=Depends(require_roles("admin", "manager"))):
    r = await db.categories.update_one({"id": cid}, {"$set": {"name": body.name, "subcategories": body.subcategories}})
    if r.matched_count == 0:
        raise HTTPException(404)
    await log_audit(user["id"], "update_category", "category", cid)
    return {"ok": True}

@api.delete("/categories/{cid}")
async def delete_category(cid: str, user=Depends(require_roles("admin", "manager"))):
    await db.categories.delete_one({"id": cid})
    await log_audit(user["id"], "delete_category", "category", cid)
    return {"ok": True}

# ---------- Tickets ----------

async def next_ticket_number() -> str:
    year = datetime.now(timezone.utc).year
    counter = await db.counters.find_one_and_update(
        {"key": f"ticket_{year}"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True,
    )
    seq = counter["seq"] if counter else 1
    return f"TKT-{year}-{seq:05d}"

@api.post("/tickets")
async def create_ticket(body: TicketCreate, user=Depends(get_current_user)):
    if body.priority not in PRIORITIES:
        raise HTTPException(400, "Invalid priority")
    customer_id = body.customer_id or user["id"]
    if user["role"] == "customer":
        customer_id = user["id"]
    tid = str(uuid.uuid4())
    number = await next_ticket_number()
    now = now_iso()
    # Default reported_via: if creator is a customer, it's Self-service; else Helpdesk
    default_via = "Self-service" if user["role"] == "customer" else "Helpdesk"
    doc = {
        "id": tid,
        "number": number,
        "subject": body.subject,
        "description": body.description,
        "customer_id": customer_id,
        "department": body.department,
        "category_id": body.category_id,
        "subcategory": body.subcategory,
        "priority": body.priority,
        "reported_via": body.reported_via or default_via,
        "status": "Open",
        "technician_id": None,
        "technicians": [],  # all technicians handling this ticket (primary + collaborators)
        "created_at": now,
        "assigned_at": None,
        "first_response_at": None,
        "start_work_at": None,
        "resolved_at": None,
        "closed_at": None,
        "root_cause": None,
        "resolution": None,
        "technician_notes": None,
        "documentation_complete": False,
        "attachments": body.attachments,
        "rating": None,
        "feedback": None,
        "reopen_count": 0,
        "escalated": False,
        "escalated_at": None,
        "escalated_to": None,
        "created_by": user["id"],
    }
    await db.tickets.insert_one(doc)
    on_behalf = user["role"] != "customer" and customer_id != user["id"]
    creator_label = f" (via {doc['reported_via']} by {user['name']})" if on_behalf else ""
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "created", "description": f"Ticket {number} created{creator_label}", "timestamp": now,
    })
    await log_audit(user["id"], "create_ticket", "ticket", tid, {"number": number, "priority": body.priority, "on_behalf": on_behalf, "reported_via": doc["reported_via"]})
    return await enrich_ticket(doc)

@api.get("/tickets")
async def list_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    technician_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    category_id: Optional[str] = None,
    department: Optional[str] = None,
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 200,
    user=Depends(get_current_user),
):
    query: Dict[str, Any] = {}
    if user["role"] == "customer":
        query["customer_id"] = user["id"]
    elif user["role"] == "technician":
        # technicians see tickets where they are primary OR collaborator, + unassigned
        query["$or"] = [
            {"technician_id": user["id"]},
            {"technicians": user["id"]},
            {"technician_id": None},
        ]

    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority
    if technician_id:
        query["technician_id"] = technician_id
    if customer_id:
        query["customer_id"] = customer_id
    if category_id:
        query["category_id"] = category_id
    if department:
        query["department"] = department
    if q:
        query.setdefault("$and", []).append({"$or": [
            {"subject": {"$regex": q, "$options": "i"}},
            {"number": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]})
    if date_from or date_to:
        rng = {}
        if date_from: rng["$gte"] = date_from
        if date_to: rng["$lte"] = date_to
        query["created_at"] = rng

    docs = await db.tickets.find(query).sort("created_at", -1).to_list(limit)
    return [await enrich_ticket(d) for d in docs]

@api.get("/tickets/{tid}")
async def get_ticket(tid: str, user=Depends(get_current_user)):
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    if user["role"] == "customer" and t.get("customer_id") != user["id"]:
        raise HTTPException(403)
    return await enrich_ticket(t)

@api.get("/tickets/{tid}/activities")
async def ticket_activities(tid: str, _=Depends(get_current_user)):
    docs = await db.ticket_activities.find({"ticket_id": tid}, {"_id": 0}).sort("timestamp", 1).to_list(500)
    return docs

@api.post("/tickets/{tid}/assign")
async def assign_ticket(tid: str, body: TicketAssign, user=Depends(require_roles("admin", "manager", "supervisor"))):
    tech = await db.users.find_one({"id": body.technician_id, "role": "technician"})
    if not tech:
        raise HTTPException(404, "Technician not found")
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    # validate additional collaborators
    additional_ids = [x for x in body.additional if x and x != body.technician_id]
    if additional_ids:
        found = await db.users.count_documents({"id": {"$in": additional_ids}, "role": "technician"})
        if found != len(set(additional_ids)):
            raise HTTPException(400, "One or more collaborators are not technicians")
    now = now_iso()
    techs = list(dict.fromkeys([body.technician_id] + additional_ids))  # dedupe, preserve order
    upd = {
        "technician_id": body.technician_id,
        "technicians": techs,
        "assigned_at": t.get("assigned_at") or now,
        "status": "Assigned" if t["status"] == "Open" else t["status"],
    }
    await db.tickets.update_one({"id": tid}, {"$set": upd})
    desc = f"Assigned to {tech['name']}" + (f" (+{len(additional_ids)} collaborator{'s' if len(additional_ids)!=1 else ''})" if additional_ids else "")
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "assigned", "description": desc, "timestamp": now,
    })
    await log_audit(user["id"], "assign_ticket", "ticket", tid, {"technician_id": body.technician_id, "collaborators": additional_ids})
    await notify_all(
        f"🎫 <b>Ticket Assigned</b>\n"
        f"{t['number']} — {t['subject']}\n"
        f"Priority: {t['priority']}\n"
        f"Primary: {tech['name']}"
        + (f"\nCollaborators: {len(additional_ids)}" if additional_ids else "")
    )
    return {"ok": True}

@api.post("/tickets/{tid}/collaborators")
async def add_collaborators(tid: str, body: TicketCollaborators, user=Depends(require_roles("admin", "manager", "supervisor"))):
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    if not t.get("technician_id"):
        raise HTTPException(400, "Assign a primary technician first")
    ids = [x for x in body.technician_ids if x]
    if not ids:
        raise HTTPException(400, "No technicians provided")
    found_techs = await db.users.find({"id": {"$in": ids}, "role": "technician"}, {"_id": 0}).to_list(50)
    if len(found_techs) != len(set(ids)):
        raise HTTPException(400, "One or more not technicians")
    current = t.get("technicians") or ([t["technician_id"]] if t.get("technician_id") else [])
    merged = list(dict.fromkeys(current + ids))
    added = [x for x in ids if x not in current]
    if not added:
        return {"ok": True, "already_present": True}
    await db.tickets.update_one({"id": tid}, {"$set": {"technicians": merged}})
    added_names = ", ".join(x["name"] for x in found_techs if x["id"] in added)
    now = now_iso()
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "collaborator_added", "description": f"Collaborator{'s' if len(added)!=1 else ''} added: {added_names}", "timestamp": now,
    })
    await log_audit(user["id"], "add_collaborators", "ticket", tid, {"added": added})
    return {"ok": True, "technicians": merged}

@api.delete("/tickets/{tid}/collaborators/{coll_id}")
async def remove_collaborator(tid: str, coll_id: str, user=Depends(require_roles("admin", "manager", "supervisor"))):
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    if coll_id == t.get("technician_id"):
        raise HTTPException(400, "Cannot remove primary technician. Reassign first.")
    current = t.get("technicians") or []
    if coll_id not in current:
        raise HTTPException(404, "Not a collaborator")
    new_list = [x for x in current if x != coll_id]
    await db.tickets.update_one({"id": tid}, {"$set": {"technicians": new_list}})
    tech = await db.users.find_one({"id": coll_id}, {"_id": 0})
    now = now_iso()
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "collaborator_removed", "description": f"Removed collaborator: {tech['name'] if tech else coll_id}", "timestamp": now,
    })
    await log_audit(user["id"], "remove_collaborator", "ticket", tid, {"removed": coll_id})
    return {"ok": True, "technicians": new_list}

@api.post("/tickets/{tid}/status")
async def change_status(tid: str, body: TicketStatusUpdate, user=Depends(get_current_user)):
    if body.status not in STATUSES:
        raise HTTPException(400, "Invalid status")
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    if user["role"] == "customer":
        raise HTTPException(403)
    if user["role"] == "technician" and user["id"] not in (t.get("technicians") or []) and t.get("technician_id") != user["id"]:
        raise HTTPException(403, "Not your ticket")
    now = now_iso()
    upd: Dict[str, Any] = {"status": body.status}
    if body.status == "On Progress":
        if not t.get("first_response_at"):
            upd["first_response_at"] = now
        if not t.get("start_work_at"):
            upd["start_work_at"] = now
    if body.status == "Reopened":
        upd["reopen_count"] = (t.get("reopen_count") or 0) + 1
        upd["resolved_at"] = None
        upd["closed_at"] = None
    if body.status == "Closed":
        upd["closed_at"] = now
    await db.tickets.update_one({"id": tid}, {"$set": upd})
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "status_change", "description": f"Status → {body.status}" + (f" — {body.note}" if body.note else ""), "timestamp": now,
    })
    await log_audit(user["id"], "status_change", "ticket", tid, {"status": body.status})
    return {"ok": True}

@api.post("/tickets/{tid}/resolve")
async def resolve_ticket(tid: str, body: TicketResolve, user=Depends(get_current_user)):
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    if user["role"] == "customer":
        raise HTTPException(403)
    if user["role"] == "technician" and user["id"] not in (t.get("technicians") or []) and t.get("technician_id") != user["id"]:
        raise HTTPException(403)
    now = now_iso()
    upd = {
        "root_cause": body.root_cause,
        "resolution": body.resolution,
        "technician_notes": body.technician_notes,
        "documentation_complete": body.documentation_complete,
        "resolved_at": now,
        "status": "Resolved",
    }
    if not t.get("first_response_at"):
        upd["first_response_at"] = now
    await db.tickets.update_one({"id": tid}, {"$set": upd})
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "resolved", "description": f"Resolved: {body.resolution[:80]}", "timestamp": now,
    })
    await log_audit(user["id"], "resolve_ticket", "ticket", tid)
    return {"ok": True}

@api.post("/tickets/{tid}/rate")
async def rate_ticket(tid: str, body: TicketRate, user=Depends(get_current_user)):
    if body.rating < 1 or body.rating > 5:
        raise HTTPException(400, "Rating 1-5")
    t = await db.tickets.find_one({"id": tid})
    if not t:
        raise HTTPException(404)
    if user["role"] == "customer" and t.get("customer_id") != user["id"]:
        raise HTTPException(403)
    if t["status"] not in ("Resolved", "Closed"):
        raise HTTPException(400, "Ticket must be resolved to rate")
    now = now_iso()
    upd = {"rating": body.rating, "feedback": body.feedback}
    if t["status"] == "Resolved":
        upd["status"] = "Closed"
        upd["closed_at"] = now
    await db.tickets.update_one({"id": tid}, {"$set": upd})
    await db.ticket_activities.insert_one({
        "id": str(uuid.uuid4()), "ticket_id": tid, "user_id": user["id"],
        "type": "rated", "description": f"Rated {body.rating}/5", "timestamp": now,
    })
    await log_audit(user["id"], "rate_ticket", "ticket", tid, {"rating": body.rating})
    return {"ok": True}

# ---------- Settings: SLA, KPI, integrations ----------

@api.get("/settings/sla")
async def get_sla(_=Depends(get_current_user)):
    return await get_sla_rules()

@api.put("/settings/sla")
async def put_sla(body: SLARulesIn, user=Depends(require_roles("admin", "manager"))):
    await db.settings.update_one({"key": "sla_rules"}, {"$set": {"key": "sla_rules", "value": body.rules}}, upsert=True)
    await log_audit(user["id"], "update_sla", "settings", "sla_rules")
    return {"ok": True}

@api.get("/settings/kpi")
async def get_kpi(_=Depends(get_current_user)):
    return await get_kpi_config()

@api.put("/settings/kpi")
async def put_kpi(body: KPIConfigIn, user=Depends(require_roles("admin", "manager"))):
    total = sum(body.weights.values())
    if abs(total - 100) > 0.01:
        raise HTTPException(400, f"Weights must sum to 100, got {total}")
    payload = {"weights": body.weights, "thresholds": body.thresholds, "productivity_target": body.productivity_target}
    await db.settings.update_one({"key": "kpi_config"}, {"$set": {"key": "kpi_config", "value": payload}}, upsert=True)
    await log_audit(user["id"], "update_kpi_config", "settings", "kpi_config")
    return {"ok": True}

@api.get("/settings/integrations")
async def get_integrations(_=Depends(require_roles("admin", "manager"))):
    doc = await db.settings.find_one({"key": "integrations"})
    return doc["value"] if doc else {"telegram_bot_token": "", "telegram_chat_id": "", "whatsapp_provider": "", "whatsapp_api_key": "", "whatsapp_sender": ""}

@api.put("/settings/integrations")
async def put_integrations(body: SettingsIn, user=Depends(require_roles("admin", "manager"))):
    await db.settings.update_one({"key": "integrations"}, {"$set": {"key": "integrations", "value": body.model_dump()}}, upsert=True)
    await log_audit(user["id"], "update_integrations", "settings", "integrations")
    return {"ok": True}

# ---------- KPI Calculation ----------

async def compute_kpi_for_technician(tech_id: str, date_from: Optional[str], date_to: Optional[str], config: Dict[str, Any]) -> Dict[str, Any]:
    # Include tickets where technician is primary OR in the technicians[] collaborator list
    q: Dict[str, Any] = {"$or": [{"technician_id": tech_id}, {"technicians": tech_id}]}
    if date_from or date_to:
        rng = {}
        if date_from: rng["$gte"] = date_from
        if date_to: rng["$lte"] = date_to
        q["created_at"] = rng
    tickets = await db.tickets.find(q).to_list(2000)

    total = len(tickets)
    resolved_states = ["Resolved", "Closed"]
    resolved_tickets = [t for t in tickets if t.get("status") in resolved_states]
    resolved_count = len(resolved_tickets)

    # Fair-share weighted points: split among all technicians on the ticket
    def share(t):
        n = max(1, len(t.get("technicians") or ([t["technician_id"]] if t.get("technician_id") else [tech_id])))
        return PRIORITY_WEIGHTS.get(t["priority"], 2) / n
    weighted_point = round(sum(share(t) for t in resolved_tickets), 2)

    reopen_total = sum((t.get("reopen_count") or 0) for t in tickets)
    reopen_rate = (reopen_total / total * 100) if total else 0

    ratings = [t["rating"] for t in tickets if t.get("rating")]
    avg_rating = sum(ratings) / len(ratings) if ratings else 0

    # SLA compliance & timings
    rules = await get_sla_rules()
    sla_ok_count = 0
    sla_eligible = 0
    resp_times = []
    resl_times = []
    doc_ok = 0
    for t in resolved_tickets:
        r = rules.get(t["priority"], DEFAULT_SLA[t["priority"]])
        rt = minutes_between(t.get("created_at"), t.get("first_response_at") or t.get("assigned_at"))
        rl = minutes_between(t.get("created_at"), t.get("resolved_at"))
        if rt is not None: resp_times.append(rt)
        if rl is not None: resl_times.append(rl)
        if rt is not None and rl is not None:
            sla_eligible += 1
            if rt <= r["response"] and rl <= r["resolution"]:
                sla_ok_count += 1
        if t.get("documentation_complete"):
            doc_ok += 1

    sla_compliance = (sla_ok_count / sla_eligible * 100) if sla_eligible else 0
    avg_response = sum(resp_times) / len(resp_times) if resp_times else 0
    avg_resolution = sum(resl_times) / len(resl_times) if resl_times else 0

    # Score components (0-100 each)
    w = config["weights"]
    productivity_target = config.get("productivity_target", 30)

    def response_score() -> float:
        # avg_response relative to weighted target (use medium priority default)
        target = rules.get("Medium", DEFAULT_SLA["Medium"])["response"]
        if not resp_times: return 0
        ratio = target / max(avg_response, 1)
        return max(0, min(100, ratio * 100))

    def resolution_score() -> float:
        target = rules.get("Medium", DEFAULT_SLA["Medium"])["resolution"]
        if not resl_times: return 0
        ratio = target / max(avg_resolution, 1)
        return max(0, min(100, ratio * 100))

    def productivity_score() -> float:
        return max(0, min(100, (weighted_point / productivity_target) * 100)) if productivity_target else 0

    def reopen_score() -> float:
        return max(0, 100 - (reopen_rate * 5))

    def rating_score() -> float:
        return (avg_rating / 5.0) * 100 if avg_rating else 0

    def doc_score() -> float:
        return (doc_ok / resolved_count * 100) if resolved_count else 0

    components = {
        "sla_compliance": sla_compliance,
        "productivity": productivity_score(),
        "response_time": response_score(),
        "resolution_time": resolution_score(),
        "reopen_rate": reopen_score(),
        "customer_rating": rating_score(),
        "documentation": doc_score(),
    }

    kpi_score = sum(components[k] * (w.get(k, 0) / 100.0) for k in components)

    thr = config["thresholds"]
    if kpi_score >= thr["excellent"]:
        performance = "Excellent"
    elif kpi_score >= thr["good"]:
        performance = "Good"
    elif kpi_score >= thr["fair"]:
        performance = "Fair"
    else:
        performance = "Needs Improvement"

    return {
        "technician_id": tech_id,
        "total_tickets": total,
        "resolved_tickets": resolved_count,
        "weighted_point": weighted_point,
        "sla_compliance": round(sla_compliance, 1),
        "avg_response_min": round(avg_response, 1),
        "avg_resolution_min": round(avg_resolution, 1),
        "reopen_rate": round(reopen_rate, 1),
        "avg_rating": round(avg_rating, 2),
        "documentation_pct": round((doc_ok / resolved_count * 100) if resolved_count else 0, 1),
        "components": {k: round(v, 1) for k, v in components.items()},
        "kpi_score": round(kpi_score, 1),
        "performance": performance,
    }

@api.get("/kpi/scores")
async def kpi_scores(date_from: Optional[str] = None, date_to: Optional[str] = None, user=Depends(get_current_user)):
    if user["role"] == "customer":
        raise HTTPException(403)
    techs = await db.users.find({"role": "technician", "active": True}).to_list(500)
    config = await get_kpi_config()
    result = []
    for t in techs:
        s = await compute_kpi_for_technician(t["id"], date_from, date_to, config)
        s["technician_name"] = t["name"]
        s["department"] = t.get("department")
        result.append(s)
    result.sort(key=lambda x: -x["kpi_score"])
    return result

@api.get("/kpi/scores/{tech_id}")
async def kpi_score_one(tech_id: str, date_from: Optional[str] = None, date_to: Optional[str] = None, user=Depends(get_current_user)):
    if user["role"] == "customer":
        raise HTTPException(403)
    if user["role"] == "technician" and user["id"] != tech_id:
        raise HTTPException(403)
    config = await get_kpi_config()
    s = await compute_kpi_for_technician(tech_id, date_from, date_to, config)
    tech = await db.users.find_one({"id": tech_id})
    if tech:
        s["technician_name"] = tech["name"]
        s["department"] = tech.get("department")
    return s

# ---------- Dashboard ----------

@api.get("/dashboard/summary")
async def dashboard_summary(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    department: Optional[str] = None,
    priority: Optional[str] = None,
    user=Depends(get_current_user),
):
    q: Dict[str, Any] = {}
    if user["role"] == "customer":
        q["customer_id"] = user["id"]
    if user["role"] == "technician":
        q["technician_id"] = user["id"]
    if date_from or date_to:
        rng = {}
        if date_from: rng["$gte"] = date_from
        if date_to: rng["$lte"] = date_to
        q["created_at"] = rng
    if department: q["department"] = department
    if priority: q["priority"] = priority

    tickets = await db.tickets.find(q).to_list(5000)

    counts = {s: 0 for s in STATUSES}
    by_priority = {p: 0 for p in PRIORITIES}
    by_category: Dict[str, int] = {}
    by_technician: Dict[str, int] = {}
    resp_times, resl_times, ratings = [], [], []
    sla_ok = sla_total = 0
    weighted_point = 0
    reopen_total = 0

    rules = await get_sla_rules()
    ticket_ids = []
    # per month
    by_month: Dict[str, int] = {}

    for t in tickets:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
        by_priority[t["priority"]] = by_priority.get(t["priority"], 0) + 1
        by_category[t.get("category_id") or "uncategorized"] = by_category.get(t.get("category_id") or "uncategorized", 0) + 1
        by_technician[t.get("technician_id") or "unassigned"] = by_technician.get(t.get("technician_id") or "unassigned", 0) + 1
        reopen_total += t.get("reopen_count") or 0
        if t.get("rating"): ratings.append(t["rating"])
        if t["status"] in ("Resolved", "Closed"):
            weighted_point += PRIORITY_WEIGHTS.get(t["priority"], 2)
            rt = minutes_between(t["created_at"], t.get("first_response_at") or t.get("assigned_at"))
            rl = minutes_between(t["created_at"], t.get("resolved_at"))
            if rt is not None: resp_times.append(rt)
            if rl is not None: resl_times.append(rl)
            r = rules.get(t["priority"], DEFAULT_SLA[t["priority"]])
            if rt is not None and rl is not None:
                sla_total += 1
                if rt <= r["response"] and rl <= r["resolution"]:
                    sla_ok += 1
        # month
        dt = parse_iso(t["created_at"])
        mkey = dt.strftime("%Y-%m")
        by_month[mkey] = by_month.get(mkey, 0) + 1

    # resolve category names
    cats = {c["id"]: c["name"] for c in await db.categories.find({}, {"_id": 0}).to_list(500)}
    by_category_named = [{"name": cats.get(k, "Uncategorized"), "value": v} for k, v in by_category.items()]

    techs = {u["id"]: u["name"] for u in await db.users.find({"role": "technician"}, {"_id": 0}).to_list(500)}
    by_tech_named = [{"name": techs.get(k, "Unassigned"), "value": v} for k, v in by_technician.items()]

    return {
        "total": len(tickets),
        "counts": counts,
        "by_priority": [{"name": p, "value": v} for p, v in by_priority.items()],
        "by_category": by_category_named,
        "by_technician": by_tech_named,
        "by_month": [{"month": k, "value": v} for k, v in sorted(by_month.items())],
        "sla_compliance": round((sla_ok / sla_total * 100) if sla_total else 0, 1),
        "sla_violation": sla_total - sla_ok,
        "avg_response_min": round(sum(resp_times) / len(resp_times), 1) if resp_times else 0,
        "avg_resolution_min": round(sum(resl_times) / len(resl_times), 1) if resl_times else 0,
        "avg_rating": round(sum(ratings) / len(ratings), 2) if ratings else 0,
        "weighted_point": weighted_point,
        "reopen_total": reopen_total,
    }

# ---------- Audit logs ----------

@api.get("/audit-logs")
async def audit_logs(limit: int = 200, user=Depends(require_roles("admin", "manager"))):
    docs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    user_ids = list({d["user_id"] for d in docs})
    users_map = {u["id"]: u["name"] for u in await db.users.find({"id": {"$in": user_ids}}, {"_id": 0}).to_list(500)}
    for d in docs:
        d["user_name"] = users_map.get(d["user_id"], "Unknown")
    return docs

# ---------- Reports Export ----------

async def _kpi_rows(date_from, date_to):
    techs = await db.users.find({"role": "technician", "active": True}).to_list(500)
    config = await get_kpi_config()
    rows = []
    for t in techs:
        s = await compute_kpi_for_technician(t["id"], date_from, date_to, config)
        rows.append([t["name"], s["total_tickets"], s["resolved_tickets"], s["weighted_point"],
                     f"{s['sla_compliance']}%", f"{s['avg_response_min']}m", f"{s['avg_resolution_min']}m",
                     f"{s['reopen_rate']}%", s["avg_rating"], s["kpi_score"], s["performance"]])
    return rows

def _csv_response(headers: List[str], rows: List[List[Any]], filename: str) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for r in rows: w.writerow(r)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})

def _pdf_response(title: str, headers: List[str], rows: List[List[Any]], filename: str) -> StreamingResponse:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet()
    elems = [Paragraph(f"<b>{title}</b>", styles["Title"]),
             Paragraph(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
             Spacer(1, 12)]
    data = [headers] + [[str(c) for c in r] for r in rows]
    tbl = Table(data, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(tbl)
    doc.build(elems)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})

@api.get("/reports/kpi/export")
async def export_kpi(fmt: str = "csv", date_from: Optional[str] = None, date_to: Optional[str] = None, user=Depends(require_roles("admin", "manager", "supervisor"))):
    rows = await _kpi_rows(date_from, date_to)
    headers = ["Technician", "Total Ticket", "Resolved", "Weighted Point", "SLA %", "Avg Response", "Avg Resolution", "Reopen %", "Rating", "KPI Score", "Performance"]
    if fmt == "pdf":
        return _pdf_response("KPI Report", headers, rows, "kpi_report.pdf")
    return _csv_response(headers, rows, "kpi_report.csv")

@api.get("/reports/tickets/export")
async def export_tickets(fmt: str = "csv", status: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None, user=Depends(require_roles("admin", "manager", "supervisor"))):
    q: Dict[str, Any] = {}
    if status: q["status"] = status
    if date_from or date_to:
        rng = {}
        if date_from: rng["$gte"] = date_from
        if date_to: rng["$lte"] = date_to
        q["created_at"] = rng
    tickets = await db.tickets.find(q).sort("created_at", -1).to_list(5000)
    users_map = {u["id"]: u["name"] for u in await db.users.find({}, {"_id": 0}).to_list(500)}
    cats = {c["id"]: c["name"] for c in await db.categories.find({}, {"_id": 0}).to_list(500)}
    rows = []
    rules = await get_sla_rules()
    for t in tickets:
        rt = minutes_between(t["created_at"], t.get("first_response_at"))
        rl = minutes_between(t["created_at"], t.get("resolved_at"))
        r = rules.get(t["priority"], DEFAULT_SLA[t["priority"]])
        sla_ok = ""
        if rt is not None and rl is not None:
            sla_ok = "OK" if (rt <= r["response"] and rl <= r["resolution"]) else "VIOLATED"
        rows.append([
            t["number"], t["subject"], t["priority"], t["status"],
            cats.get(t.get("category_id"), "-"),
            users_map.get(t.get("customer_id"), "-"),
            users_map.get(t.get("technician_id"), "Unassigned"),
            t["created_at"][:19], (t.get("resolved_at") or "")[:19],
            f"{round(rt,1)}" if rt is not None else "-",
            f"{round(rl,1)}" if rl is not None else "-",
            sla_ok, t.get("rating") or "-",
        ])
    headers = ["Number", "Subject", "Priority", "Status", "Category", "Customer", "Technician", "Created", "Resolved", "Response(m)", "Resolution(m)", "SLA", "Rating"]
    if fmt == "pdf":
        return _pdf_response("Tickets Report", headers, rows, "tickets_report.pdf")
    return _csv_response(headers, rows, "tickets_report.csv")

@api.get("/reports/aging")
async def ticket_aging(user=Depends(get_current_user)):
    if user["role"] == "customer":
        raise HTTPException(403)
    tickets = await db.tickets.find({"status": {"$nin": ["Closed", "Resolved"]}}).to_list(5000)
    buckets = {"<1h": 0, "1-4h": 0, "4-8h": 0, "8-24h": 0, "1-3d": 0, ">3d": 0}
    at_risk = 0
    rules = await get_sla_rules()
    now = datetime.now(timezone.utc)
    for t in tickets:
        age_min = (now - parse_iso(t["created_at"])).total_seconds() / 60
        if age_min < 60: buckets["<1h"] += 1
        elif age_min < 240: buckets["1-4h"] += 1
        elif age_min < 480: buckets["4-8h"] += 1
        elif age_min < 1440: buckets["8-24h"] += 1
        elif age_min < 4320: buckets["1-3d"] += 1
        else: buckets[">3d"] += 1
        target = rules.get(t["priority"], DEFAULT_SLA[t["priority"]])["resolution"]
        if age_min > target * 0.75:
            at_risk += 1
    return {"buckets": [{"range": k, "value": v} for k, v in buckets.items()], "at_risk": at_risk, "total_open": len(tickets)}

# ---------- Seeding ----------

async def seed_data():
    # Indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("username", unique=True)
    await db.tickets.create_index("number", unique=True)
    await db.tickets.create_index("created_at")
    await db.audit_logs.create_index("timestamp")

    admin_email = os.environ.get("ADMIN_EMAIL", "admin@itsm.local").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()), "email": admin_email, "username": "admin",
            "name": "System Admin", "role": "admin", "department": "IT",
            "phone": "+62-800-0000", "active": True,
            "password_hash": hash_pw(admin_password), "created_at": now_iso(),
        })
    elif not verify_pw(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_pw(admin_password)}})

    if await db.users.count_documents({}) <= 1:
        demo = [
            ("manager@itsm.local", "manager", "Rita Manager", "manager", "IT"),
            ("supervisor@itsm.local", "supervisor", "Bagas Supervisor", "supervisor", "IT"),
            ("tech1@itsm.local", "tech1", "Andi Wijaya", "technician", "IT-Infra"),
            ("tech2@itsm.local", "tech2", "Siti Rahmawati", "technician", "IT-Apps"),
            ("tech3@itsm.local", "tech3", "Deni Pratama", "technician", "IT-Support"),
            ("customer1@itsm.local", "customer1", "Fajar Nugraha", "customer", "Finance"),
            ("customer2@itsm.local", "customer2", "Linda Susanti", "customer", "HR"),
        ]
        for email, uname, name, role, dept in demo:
            await db.users.insert_one({
                "id": str(uuid.uuid4()), "email": email, "username": uname,
                "name": name, "role": role, "department": dept,
                "phone": "+62-812-3456", "active": True,
                "password_hash": hash_pw("password123"), "created_at": now_iso(),
            })

    if await db.categories.count_documents({}) == 0:
        cats = [
            ("Hardware", ["Laptop", "Desktop", "Printer", "Network Device"]),
            ("Software", ["Office", "ERP", "Antivirus", "OS"]),
            ("Network", ["WiFi", "VPN", "LAN"]),
            ("Access", ["Account", "Password Reset", "Permission"]),
            ("Email", ["Delivery Issue", "Spam", "Configuration"]),
        ]
        for name, subs in cats:
            await db.categories.insert_one({"id": str(uuid.uuid4()), "name": name, "subcategories": subs, "created_at": now_iso()})

    if not await db.settings.find_one({"key": "sla_rules"}):
        await db.settings.insert_one({"key": "sla_rules", "value": DEFAULT_SLA})
    if not await db.settings.find_one({"key": "kpi_config"}):
        await db.settings.insert_one({"key": "kpi_config", "value": DEFAULT_KPI})
    if not await db.settings.find_one({"key": "integrations"}):
        await db.settings.insert_one({"key": "integrations", "value": {"telegram_bot_token": "", "telegram_chat_id": "", "whatsapp_provider": "", "whatsapp_api_key": "", "whatsapp_sender": ""}})

    # Seed tickets
    if await db.tickets.count_documents({}) == 0:
        techs = await db.users.find({"role": "technician"}, {"_id": 0}).to_list(10)
        customers = await db.users.find({"role": "customer"}, {"_id": 0}).to_list(10)
        cats_list = await db.categories.find({}, {"_id": 0}).to_list(20)
        import random
        random.seed(42)
        subjects = [
            ("Laptop won't boot", "My laptop shows blue screen and reboots continuously.", "Hardware", "Laptop", "High"),
            ("Cannot access ERP", "Login page returns 500 error since morning.", "Software", "ERP", "Critical"),
            ("Printer paper jam", "The printer on 3rd floor jams every print job.", "Hardware", "Printer", "Medium"),
            ("VPN disconnected", "VPN keeps dropping every 5 minutes.", "Network", "VPN", "High"),
            ("Password reset needed", "Forgot password for corporate email.", "Access", "Password Reset", "Low"),
            ("Email not sending", "Outgoing emails stuck in outbox.", "Email", "Delivery Issue", "Medium"),
            ("WiFi slow in meeting room", "Extremely slow WiFi in Room A.", "Network", "WiFi", "Medium"),
            ("Office 365 activation", "Office asks to activate again.", "Software", "Office", "Low"),
            ("Antivirus popup errors", "Constant popups from antivirus.", "Software", "Antivirus", "Low"),
            ("Server room AC alert", "AC unit in server room offline.", "Hardware", "Network Device", "Critical"),
            ("New user account", "Need account for new hire in Finance.", "Access", "Account", "Medium"),
            ("Monitor flicker", "Monitor flickers randomly during work.", "Hardware", "Desktop", "Medium"),
            ("Shared folder access", "Cannot access finance shared folder.", "Access", "Permission", "High"),
            ("Zoom call quality poor", "Zoom lags in team meetings.", "Network", "WiFi", "Medium"),
            ("PDF viewer crash", "Adobe crashes when opening large PDF.", "Software", "Office", "Low"),
        ]

        now = datetime.now(timezone.utc)
        for i, (subj, desc, cat_name, subc, prio) in enumerate(subjects):
            cat = next((c for c in cats_list if c["name"] == cat_name), None)
            cust = customers[i % len(customers)]
            tech = techs[i % len(techs)]
            days_ago = random.randint(0, 25)
            created = (now - timedelta(days=days_ago, hours=random.randint(0, 20))).isoformat()
            number = await next_ticket_number()
            resolved = None; closed = None; status = "Open"; rating = None; feedback = None
            first_resp = None; start_work = None; assigned = None
            reopen_count = 0; docs_ok = False; root_cause = None; resolution = None; tech_notes = None
            outcome = random.random()
            if outcome < 0.65:  # Closed
                assigned = (parse_iso(created) + timedelta(minutes=random.randint(5, 30))).isoformat()
                first_resp = (parse_iso(created) + timedelta(minutes=random.randint(5, 60))).isoformat()
                start_work = first_resp
                resolved = (parse_iso(created) + timedelta(minutes=random.randint(60, 800))).isoformat()
                closed = (parse_iso(resolved) + timedelta(hours=random.randint(1, 12))).isoformat()
                status = "Closed"
                rating = random.choice([3, 4, 4, 5, 5, 5])
                feedback = random.choice(["Cepat dan tuntas.", "Solusi tepat.", "Terima kasih.", "Response bagus.", None])
                root_cause = "Driver corruption / config error / hardware failure"
                resolution = f"Applied fix: reinstall & verify. {subj} resolved."
                tech_notes = "Verified with user."
                docs_ok = random.random() > 0.2
                if random.random() < 0.1: reopen_count = 1
            elif outcome < 0.85:  # In progress
                assigned = (parse_iso(created) + timedelta(minutes=random.randint(5, 30))).isoformat()
                first_resp = assigned
                start_work = first_resp
                status = random.choice(["On Progress", "Assigned", "Pending"])
            else:  # Open
                status = "Open"

            doc = {
                "id": str(uuid.uuid4()), "number": number, "subject": subj, "description": desc,
                "customer_id": cust["id"], "department": cust["department"],
                "category_id": cat["id"] if cat else None, "subcategory": subc, "priority": prio,
                "status": status, "technician_id": tech["id"] if status != "Open" else None,
                "created_at": created, "assigned_at": assigned, "first_response_at": first_resp,
                "start_work_at": start_work, "resolved_at": resolved, "closed_at": closed,
                "root_cause": root_cause, "resolution": resolution, "technician_notes": tech_notes,
                "documentation_complete": docs_ok, "attachments": [], "rating": rating, "feedback": feedback,
                "reopen_count": reopen_count, "created_by": cust["id"],
            }
            await db.tickets.insert_one(doc)
            await db.ticket_activities.insert_one({
                "id": str(uuid.uuid4()), "ticket_id": doc["id"], "user_id": cust["id"],
                "type": "created", "description": f"Ticket {number} created", "timestamp": created,
            })
            if assigned:
                await db.ticket_activities.insert_one({
                    "id": str(uuid.uuid4()), "ticket_id": doc["id"], "user_id": tech["id"],
                    "type": "assigned", "description": f"Assigned to {tech['name']}", "timestamp": assigned,
                })
            if resolved:
                await db.ticket_activities.insert_one({
                    "id": str(uuid.uuid4()), "ticket_id": doc["id"], "user_id": tech["id"],
                    "type": "resolved", "description": resolution, "timestamp": resolved,
                })
            if rating:
                await db.ticket_activities.insert_one({
                    "id": str(uuid.uuid4()), "ticket_id": doc["id"], "user_id": cust["id"],
                    "type": "rated", "description": f"Rated {rating}/5", "timestamp": closed,
                })

    logger.info("Seeding complete.")

    # Backfill: ensure every ticket with a primary technician has a technicians[] array
    async for t in db.tickets.find({"technician_id": {"$ne": None}, "technicians": {"$in": [None, []]}}):
        await db.tickets.update_one({"id": t["id"]}, {"$set": {"technicians": [t["technician_id"]]}})

@app.on_event("startup")
async def on_startup():
    await seed_data()

@app.on_event("shutdown")
async def on_shutdown():
    client.close()

# ---------- Notifications ----------

async def get_integrations_cfg() -> Dict[str, Any]:
    doc = await db.settings.find_one({"key": "integrations"})
    return doc["value"] if doc else {}

async def send_telegram(text: str) -> Dict[str, Any]:
    cfg = await get_integrations_cfg()
    token = (cfg.get("telegram_bot_token") or "").strip()
    chat = (cfg.get("telegram_chat_id") or "").strip()
    if not token or not chat:
        return {"ok": False, "reason": "not_configured"}
    try:
        async with httpx.AsyncClient(timeout=8) as h:
            r = await h.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": text, "parse_mode": "HTML"},
            )
            return {"ok": r.status_code == 200, "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        logger.warning(f"telegram error: {e}")
        return {"ok": False, "error": str(e)}

async def send_whatsapp(text: str, target: Optional[str] = None) -> Dict[str, Any]:
    cfg = await get_integrations_cfg()
    provider = (cfg.get("whatsapp_provider") or "").strip().lower()
    api_key = (cfg.get("whatsapp_api_key") or "").strip()
    sender = (cfg.get("whatsapp_sender") or "").strip()
    if not provider or not api_key or not sender:
        return {"ok": False, "reason": "not_configured"}
    dest = target or sender
    try:
        async with httpx.AsyncClient(timeout=8) as h:
            if provider == "fonnte":
                r = await h.post(
                    "https://api.fonnte.com/send",
                    headers={"Authorization": api_key},
                    data={"target": dest, "message": text},
                )
            elif provider == "wablas":
                r = await h.post(
                    "https://console.wablas.com/api/send-message",
                    headers={"Authorization": api_key},
                    data={"phone": dest, "message": text},
                )
            elif provider == "twilio":
                # Twilio format: api_key is "SID:AUTH_TOKEN"
                sid_auth = api_key.split(":", 1)
                if len(sid_auth) != 2:
                    return {"ok": False, "reason": "twilio_key_should_be_SID:AUTH_TOKEN"}
                r = await h.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{sid_auth[0]}/Messages.json",
                    auth=(sid_auth[0], sid_auth[1]),
                    data={"From": f"whatsapp:{sender}", "To": f"whatsapp:{dest}", "Body": text},
                )
            else:
                return {"ok": False, "reason": f"unknown_provider:{provider}"}
            return {"ok": r.status_code < 400, "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        logger.warning(f"whatsapp error: {e}")
        return {"ok": False, "error": str(e)}

async def notify_all(text: str, target: Optional[str] = None):
    """Fire-and-forget notification to both channels."""
    async def _run():
        await asyncio.gather(send_telegram(text), send_whatsapp(text, target), return_exceptions=True)
    asyncio.create_task(_run())

# ---------- Cron endpoints ----------

WEBHOOK_CRON_SECRET = os.environ.get("WEBHOOK_CRON_SECRET", "")

def verify_cron_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer")
    token = auth[7:]
    if not WEBHOOK_CRON_SECRET or not hmac.compare_digest(token, WEBHOOK_CRON_SECRET):
        raise HTTPException(401, "Invalid webhook secret")

@api.post("/cron/kpi-snapshot")
async def cron_kpi_snapshot(request: Request):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    verify_cron_auth(request)
    run_id = request.headers.get("X-Webhook-Id") or str(uuid.uuid4())
    async def _do():
        try:
            now = datetime.now(timezone.utc)
            # snapshot the previous month
            first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            last_month_end = first_of_this_month - timedelta(seconds=1)
            last_month_start = last_month_end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            period_key = last_month_start.strftime("%Y-%m")
            config = await get_kpi_config()
            techs = await db.users.find({"role": "technician"}).to_list(500)
            for t in techs:
                s = await compute_kpi_for_technician(t["id"], last_month_start.isoformat(), last_month_end.isoformat(), config)
                s["technician_name"] = t["name"]
                s["department"] = t.get("department")
                s["period"] = period_key
                s["snapshot_at"] = now.isoformat()
                s["run_id"] = run_id
                await db.kpi_snapshots.update_one(
                    {"technician_id": t["id"], "period": period_key},
                    {"$set": s}, upsert=True,
                )
            logger.info(f"KPI snapshot saved for {period_key}: {len(techs)} technicians")
        except Exception as e:
            logger.error(f"kpi snapshot failed: {e}")
    asyncio.create_task(_do())
    return {"ok": True, "run_id": run_id}

@api.post("/cron/sla-check")
async def cron_sla_check(request: Request):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    verify_cron_auth(request)
    run_id = request.headers.get("X-Webhook-Id") or str(uuid.uuid4())
    async def _do():
        try:
            rules = await get_sla_rules()
            now = datetime.now(timezone.utc)
            open_tickets = await db.tickets.find({"status": {"$nin": ["Closed", "Resolved"]}}).to_list(2000)
            users_map = {u["id"]: u for u in await db.users.find({}, {"_id": 0}).to_list(500)}
            supervisors = [u for u in users_map.values() if u["role"] in ("supervisor", "manager") and u.get("active", True)]
            sent = 0
            escalated_count = 0
            for t in open_tickets:
                target = rules.get(t["priority"], DEFAULT_SLA[t["priority"]])["resolution"]
                age = (now - parse_iso(t["created_at"])).total_seconds() / 60
                pct = (age / target) * 100 if target else 0
                if pct < 75:
                    continue
                level = "violated" if pct >= 100 else "warning"
                key = f"{t['id']}:{level}"
                already_dedup = await db.notify_dedup.find_one({"key": key})

                # Auto-escalate on SLA breach if not yet escalated
                if pct >= 100 and not t.get("escalated"):
                    supervisor = supervisors[0] if supervisors else None
                    upd = {"escalated": True, "escalated_at": now.isoformat(), "escalated_to": supervisor["id"] if supervisor else None}
                    await db.tickets.update_one({"id": t["id"]}, {"$set": upd})
                    await db.ticket_activities.insert_one({
                        "id": str(uuid.uuid4()), "ticket_id": t["id"],
                        "user_id": supervisor["id"] if supervisor else "system",
                        "type": "escalated",
                        "description": f"Auto-escalated to {supervisor['name'] if supervisor else 'supervisor'} — SLA breached",
                        "timestamp": now.isoformat(),
                    })
                    escalated_count += 1

                if already_dedup:
                    continue
                assignee = users_map.get(t.get("technician_id"), {}).get("name") or "Unassigned"
                header = "🚨 SLA VIOLATION — ESCALATED" if pct >= 100 else "⚠️ SLA WARNING"
                msg = (
                    f"{header}\n"
                    f"Ticket <b>{t['number']}</b> — {t['subject']}\n"
                    f"Priority: {t['priority']} · Status: {t['status']}\n"
                    f"Age: {int(age)}m / target {target}m ({int(pct)}%)\n"
                    f"Assignee: {assignee}"
                )
                await notify_all(msg)
                await db.notify_dedup.insert_one({"key": key, "created_at": now.isoformat()})
                sent += 1
            logger.info(f"SLA check: scanned {len(open_tickets)}, sent {sent} alerts, escalated {escalated_count}")
        except Exception as e:
            logger.error(f"sla check failed: {e}")
    asyncio.create_task(_do())
    return {"ok": True, "run_id": run_id}

@api.post("/cron/weekly-digest")
async def cron_weekly_digest(request: Request):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    verify_cron_auth(request)
    run_id = request.headers.get("X-Webhook-Id") or str(uuid.uuid4())
    async def _do():
        try:
            now = datetime.now(timezone.utc)
            week_ago = now - timedelta(days=7)
            date_from = week_ago.isoformat()
            date_to = now.isoformat()
            tickets = await db.tickets.find({"created_at": {"$gte": date_from, "$lte": date_to}}).to_list(5000)
            resolved = [t for t in tickets if t.get("status") in ("Resolved", "Closed")]
            config = await get_kpi_config()
            techs = await db.users.find({"role": "technician", "active": True}).to_list(500)
            rows = []
            for t in techs:
                s = await compute_kpi_for_technician(t["id"], date_from, date_to, config)
                s["name"] = t["name"]
                rows.append(s)
            rows.sort(key=lambda x: -x["kpi_score"])
            top3 = rows[:3]
            open_count = sum(1 for t in tickets if t.get("status") not in ("Closed", "Resolved"))
            ratings = [t["rating"] for t in tickets if t.get("rating")]
            weekly_avg_rating = round(sum(ratings) / len(ratings), 2) if ratings else 0

            medals = ["🥇", "🥈", "🥉"]
            top_lines = "\n".join(
                f"{medals[i]} {r['name']} — KPI {r['kpi_score']} · SLA {r['sla_compliance']}%"
                for i, r in enumerate(top3)
            )
            msg = (
                f"📊 <b>Weekly KPI Digest</b>\n"
                f"Week of {week_ago.strftime('%d %b')} → {now.strftime('%d %b %Y')}\n\n"
                f"Tickets Created: <b>{len(tickets)}</b>\n"
                f"Resolved / Closed: <b>{len(resolved)}</b>\n"
                f"Still Open: <b>{open_count}</b>\n"
                f"Avg Rating: <b>{weekly_avg_rating}/5</b>\n\n"
                f"🏆 Top Performers:\n{top_lines}\n\n"
                f"Open the dashboard for full details."
            )
            await notify_all(msg)
            await db.digest_history.insert_one({
                "id": str(uuid.uuid4()),
                "run_id": run_id,
                "period_start": date_from,
                "period_end": date_to,
                "total_tickets": len(tickets),
                "resolved": len(resolved),
                "top_performers": [{"name": r["name"], "kpi_score": r["kpi_score"]} for r in top3],
                "message": msg,
                "created_at": now.isoformat(),
            })
            logger.info(f"Weekly digest sent: {len(tickets)} tickets")
        except Exception as e:
            logger.error(f"weekly digest failed: {e}")
    asyncio.create_task(_do())
    return {"ok": True, "run_id": run_id}

@api.post("/digest/preview")
async def digest_preview(user=Depends(require_roles("admin", "manager"))):
    """Manual trigger so managers can preview and send this week's digest on demand."""
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    tickets = await db.tickets.find({"created_at": {"$gte": week_ago.isoformat()}}).to_list(5000)
    resolved = [t for t in tickets if t.get("status") in ("Resolved", "Closed")]
    config = await get_kpi_config()
    techs = await db.users.find({"role": "technician", "active": True}).to_list(500)
    rows = []
    for t in techs:
        s = await compute_kpi_for_technician(t["id"], week_ago.isoformat(), now.isoformat(), config)
        rows.append({"name": t["name"], "kpi_score": s["kpi_score"], "sla_compliance": s["sla_compliance"], "resolved": s["resolved_tickets"]})
    rows.sort(key=lambda x: -x["kpi_score"])
    return {
        "period": {"from": week_ago.isoformat(), "to": now.isoformat()},
        "tickets_created": len(tickets),
        "resolved": len(resolved),
        "open": len(tickets) - len(resolved),
        "top_performers": rows[:5],
    }

# ---------- Public Status Page ----------

@api.get("/monitoring/mttr")
async def monitoring_mttr(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    user=Depends(require_roles("admin", "manager", "supervisor")),
):
    """Aggregate MTTR (Mean Time To Resolve) across department / technician / priority + weekly trend."""
    q: Dict[str, Any] = {"status": {"$in": ["Resolved", "Closed"]}}
    if date_from or date_to:
        rng = {}
        if date_from: rng["$gte"] = date_from
        if date_to: rng["$lte"] = date_to
        q["created_at"] = rng
    tickets = await db.tickets.find(q).to_list(5000)
    users_map = {u["id"]: u for u in await db.users.find({}, {"_id": 0}).to_list(1000)}

    def mttr(ts):
        vals = [minutes_between(t["created_at"], t.get("resolved_at")) for t in ts if t.get("resolved_at")]
        vals = [v for v in vals if v is not None]
        return round(sum(vals) / len(vals), 1) if vals else 0

    def resp(ts):
        vals = [minutes_between(t["created_at"], t.get("first_response_at") or t.get("assigned_at")) for t in ts]
        vals = [v for v in vals if v is not None]
        return round(sum(vals) / len(vals), 1) if vals else 0

    overall = mttr(tickets)
    overall_response = resp(tickets)

    # By technician (primary or collaborator counts)
    tech_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for t in tickets:
        ids = t.get("technicians") or ([t["technician_id"]] if t.get("technician_id") else [])
        for tid in ids:
            tech_buckets.setdefault(tid, []).append(t)
    by_technician = []
    for tid, ts in tech_buckets.items():
        u = users_map.get(tid)
        if not u or u.get("role") != "technician":
            continue
        by_technician.append({
            "technician_id": tid,
            "name": u["name"],
            "department": u.get("department"),
            "ticket_count": len(ts),
            "mttr_min": mttr(ts),
            "response_min": resp(ts),
        })
    by_technician.sort(key=lambda x: x["mttr_min"] if x["mttr_min"] > 0 else 1e12)

    # By department (customer's department = the requesting side)
    dept_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for t in tickets:
        dept = t.get("department") or "Unknown"
        dept_buckets.setdefault(dept, []).append(t)
    by_department = [
        {"department": d, "ticket_count": len(ts), "mttr_min": mttr(ts), "response_min": resp(ts)}
        for d, ts in dept_buckets.items()
    ]
    by_department.sort(key=lambda x: -x["ticket_count"])

    # By priority
    prio_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for t in tickets:
        prio_buckets.setdefault(t["priority"], []).append(t)
    by_priority = []
    for p in ["Critical", "High", "Medium", "Low"]:
        ts = prio_buckets.get(p, [])
        rules = await get_sla_rules()
        target = rules.get(p, DEFAULT_SLA[p])["resolution"]
        by_priority.append({
            "priority": p,
            "ticket_count": len(ts),
            "mttr_min": mttr(ts),
            "target_min": target,
            "compliance_pct": round(sum(1 for t in ts if (minutes_between(t["created_at"], t.get("resolved_at")) or 0) <= target) / len(ts) * 100, 1) if ts else 0,
        })

    # Weekly trend (last 12 weeks)
    now = datetime.now(timezone.utc)
    weeks: List[Dict[str, Any]] = []
    for i in range(11, -1, -1):
        end = now - timedelta(days=i * 7)
        start = end - timedelta(days=7)
        w_tickets = [t for t in tickets if start.isoformat() <= t["created_at"] < end.isoformat()]
        weeks.append({
            "week": end.strftime("%Y-W%V"),
            "label": end.strftime("%d %b"),
            "mttr_min": mttr(w_tickets),
            "response_min": resp(w_tickets),
            "ticket_count": len(w_tickets),
        })

    fastest = by_technician[:3]
    slowest = [t for t in reversed(by_technician) if t["mttr_min"] > 0][:3]

    return {
        "period": {"from": date_from, "to": date_to},
        "overall_mttr_min": overall,
        "overall_response_min": overall_response,
        "total_resolved": len(tickets),
        "by_technician": by_technician,
        "by_department": by_department,
        "by_priority": by_priority,
        "weekly_trend": weeks,
        "fastest": fastest,
        "slowest": slowest,
    }

@api.get("/public/status")
async def public_status():
    """Public unauthenticated status endpoint for customers."""
    now = datetime.now(timezone.utc)
    since_7d = (now - timedelta(days=7)).isoformat()
    rules = await get_sla_rules()

    tickets = await db.tickets.find({"created_at": {"$gte": since_7d}}).to_list(5000)
    open_tickets = await db.tickets.find({"status": {"$nin": ["Closed", "Resolved"]}}).to_list(2000)

    sla_ok = sla_total = 0
    resp_times = []; resl_times = []
    ratings = []
    for t in tickets:
        if t.get("status") in ("Resolved", "Closed"):
            rt = minutes_between(t["created_at"], t.get("first_response_at") or t.get("assigned_at"))
            rl = minutes_between(t["created_at"], t.get("resolved_at"))
            if rt is not None: resp_times.append(rt)
            if rl is not None: resl_times.append(rl)
            r = rules.get(t["priority"], DEFAULT_SLA[t["priority"]])
            if rt is not None and rl is not None:
                sla_total += 1
                if rt <= r["response"] and rl <= r["resolution"]:
                    sla_ok += 1
        if t.get("rating"): ratings.append(t["rating"])

    queue = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    critical_open = 0
    for t in open_tickets:
        queue[t["priority"]] = queue.get(t["priority"], 0) + 1
        if t["priority"] == "Critical": critical_open += 1

    active_techs = await db.users.count_documents({"role": "technician", "active": True})

    compliance = round((sla_ok / sla_total * 100) if sla_total else 0, 1)
    status = "operational"
    if critical_open >= 3 or compliance < 75:
        status = "degraded"
    if compliance < 50 and critical_open >= 5:
        status = "major_outage"

    return {
        "generated_at": now.isoformat(),
        "status": status,
        "period_days": 7,
        "queue": {
            "total_open": len(open_tickets),
            "critical_open": critical_open,
            "by_priority": [{"name": k, "value": v} for k, v in queue.items()],
        },
        "sla_compliance_7d": compliance,
        "avg_response_min_7d": round(sum(resp_times) / len(resp_times), 1) if resp_times else 0,
        "avg_resolution_min_7d": round(sum(resl_times) / len(resl_times), 1) if resl_times else 0,
        "avg_rating_7d": round(sum(ratings) / len(ratings), 2) if ratings else 0,
        "resolved_7d": len([t for t in tickets if t.get("status") in ("Resolved", "Closed")]),
        "created_7d": len(tickets),
        "active_technicians": active_techs,
    }

# ---------- KPI History + Leaderboard ----------

@api.get("/kpi/history")
async def kpi_history(technician_id: Optional[str] = None, months: int = 12, user=Depends(get_current_user)):
    if user["role"] == "customer":
        raise HTTPException(403)
    q: Dict[str, Any] = {}
    if technician_id:
        q["technician_id"] = technician_id
    docs = await db.kpi_snapshots.find(q, {"_id": 0}).sort("period", -1).to_list(500)
    docs = docs[: months * 20]
    return docs

@api.post("/kpi/snapshot-now")
async def kpi_snapshot_now(user=Depends(require_roles("admin", "manager"))):
    """Manual trigger to create a snapshot of the current month for testing/on-demand use."""
    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    period_key = period_start.strftime("%Y-%m")
    config = await get_kpi_config()
    techs = await db.users.find({"role": "technician"}).to_list(500)
    count = 0
    for t in techs:
        s = await compute_kpi_for_technician(t["id"], period_start.isoformat(), now.isoformat(), config)
        s["technician_name"] = t["name"]
        s["department"] = t.get("department")
        s["period"] = period_key
        s["snapshot_at"] = now.isoformat()
        await db.kpi_snapshots.update_one(
            {"technician_id": t["id"], "period": period_key},
            {"$set": s}, upsert=True,
        )
        count += 1
    await log_audit(user["id"], "kpi_snapshot", "kpi", period_key, {"count": count})
    return {"ok": True, "period": period_key, "count": count}

@api.get("/leaderboard")
async def leaderboard(period: Optional[str] = None, user=Depends(get_current_user)):
    """Public (any authenticated user) leaderboard.
    If period given (YYYY-MM), use snapshot; else compute current-month live."""
    if period:
        docs = await db.kpi_snapshots.find({"period": period}, {"_id": 0}).sort("kpi_score", -1).to_list(200)
        return {"period": period, "source": "snapshot", "rows": docs}
    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    config = await get_kpi_config()
    techs = await db.users.find({"role": "technician", "active": True}).to_list(500)
    rows = []
    for t in techs:
        s = await compute_kpi_for_technician(t["id"], period_start.isoformat(), now.isoformat(), config)
        rows.append({
            "technician_id": t["id"],
            "technician_name": t["name"],
            "department": t.get("department"),
            "kpi_score": s["kpi_score"],
            "weighted_point": s["weighted_point"],
            "sla_compliance": s["sla_compliance"],
            "avg_rating": s["avg_rating"],
            "total_tickets": s["total_tickets"],
            "resolved_tickets": s["resolved_tickets"],
            "performance": s["performance"],
        })
    rows.sort(key=lambda x: -x["kpi_score"])
    return {"period": period_start.strftime("%Y-%m"), "source": "live", "rows": rows}

# ---------- Notification test endpoint ----------

@api.post("/notifications/test")
async def test_notification(user=Depends(require_roles("admin", "manager"))):
    tg = await send_telegram("<b>ServiceOps test</b>\nThis is a test notification from your ITSM dashboard.")
    wa = await send_whatsapp("ServiceOps test — this is a test notification from your ITSM dashboard.")
    return {"telegram": tg, "whatsapp": wa}

# ---------- Mount ----------

app.include_router(api)

_cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=_cors_origins if _cors_origins != ["*"] else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
