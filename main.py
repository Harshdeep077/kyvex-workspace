import io
import os
import re
import hmac
import uuid
import random
import hashlib
import datetime
from typing import Optional

import pytesseract
from PIL import Image
from pdf2image import convert_from_bytes

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

# ------------------------------------------------------------
# DATABASE (put your NEW Mongo URL in the MONGO_URL env var)
# ------------------------------------------------------------
MONGO_URL = os.getenv("MONGO_URL", "mongodb+srv://harsh:harsh@employeecluster.nk1wzey.mongodb.net/")
client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=2000)
db = client.kyvex_workspace_db

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_PASSWORD = "1234"

DEFAULT_USERS = [
    {"name": "Admin User", "email": "admin@kyvex.ai", "role": "admin", "department": "Management"},
    {"name": "Mannat", "email": "mannat123@kyvex.ai", "role": "employee", "department": "Engineering"},
    {"name": "Narinder", "email": "narinder123@kyvex.ai", "role": "employee", "department": "Engineering"},
    {"name": "Harsh", "email": "harsh123@kyvex.ai", "role": "employee", "department": "Engineering"},
    {"name": "Anurag", "email": "anurag123@kyvex.ai", "role": "employee", "department": "Design"},
    {"name": "Navjot", "email": "navjot123@kyvex.ai", "role": "employee", "department": "Quality Assurance"},
    {"name": "Deepali", "email": "deepali123@kyvex.ai", "role": "employee", "department": "HR"},
    {"name": "Aarav", "email": "aarav123@kyvex.ai", "role": "employee", "department": "Engineering"},
    {"name": "Priya", "email": "priya123@kyvex.ai", "role": "employee", "department": "Marketing"},
    {"name": "Rahul", "email": "rahul123@kyvex.ai", "role": "employee", "department": "Finance"},
]


# ============================================================
#                      EMPLOYEE IDs  (e.g. 26K4821)
# ============================================================
async def generate_employee_id() -> str:
    """Year (2 digits) + 'K' + 4 random digits, guaranteed unique in the users collection."""
    prefix = datetime.datetime.now().strftime("%y") + "K"
    for _ in range(100):
        candidate = prefix + str(random.randint(1000, 9999))
        if not await db.users.find_one({"employee_id": candidate}):
            return candidate
    raise HTTPException(status_code=500, detail="Could not generate a unique employee ID")


@app.on_event("startup")
async def seed_database():
    try:
        for u in DEFAULT_USERS:
            if not await db.users.find_one({"email": u["email"]}):
                await db.users.insert_one(dict(u))

        # Unique index so two people can never share an ID (sparse = users without an ID are ignored)
        await db.users.create_index("employee_id", unique=True, sparse=True)

        # Give an ID to every existing user that doesn't have one yet
        async for u in db.users.find({"employee_id": {"$exists": False}}):
            await db.users.update_one({"_id": u["_id"]}, {"$set": {"employee_id": await generate_employee_id()}})
    except Exception as e:
        print(f"Warning: Could not connect to MongoDB on startup: {e}")


# ============================================================
#                      HELPERS
# ============================================================
def hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 100_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def public_user(user: dict) -> dict:
    return {k: v for k, v in user.items() if k not in ("password_hash", "_id")}


async def get_requester(email: Optional[str]) -> dict:
    email = (email or "").strip().lower()
    if not email:
        raise HTTPException(status_code=401, detail="Missing x-user-email header")
    try:
        user = await db.users.find_one({"email": email})
    except Exception:
        user = next((dict(u) for u in DEFAULT_USERS if u["email"] == email), None)
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user


async def require_admin(email: Optional[str]) -> dict:
    requester = await get_requester(email)
    if requester.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return requester


# ============================================================
#                  AUTH & USER ROUTES
# ============================================================
@app.post("/api/register")
@app.post("/api/signup")
async def register(data: dict):
    name = (data.get("name") or data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    department = (data.get("department") or "General").strip()
    password = data.get("password") or ""

    if not name or not email:
        raise HTTPException(status_code=400, detail="Name and email are required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    try:
        existing = await db.users.find_one({"email": email})
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    user = {
        "name": name.title(),
        "email": email,
        "department": department,
        "role": "employee",  # never trust role from the client
        "employee_id": await generate_employee_id(),
        "password_hash": hash_password(password),
    }
    try:
        await db.users.insert_one(user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not create account: {e}")

    return {"message": "Account created successfully", "user": public_user(user)}


@app.post("/api/login")
async def login(credentials: dict):
    # "identifier" can be an email OR an employee ID like 26K1234
    ident = (credentials.get("identifier") or credentials.get("email") or "").strip()
    password = credentials.get("password") or ""
    if not ident:
        raise HTTPException(status_code=400, detail="Email or Employee ID is required")

    by_email = "@" in ident
    try:
        if by_email:
            user = await db.users.find_one({"email": ident.lower()})
        else:
            user = await db.users.find_one({"employee_id": ident.upper()})
    except Exception:
        # Database offline: only preset users, only by email
        user = next((dict(u) for u in DEFAULT_USERS if u["email"] == ident.lower()), None) if by_email else None

    if not user:
        raise HTTPException(status_code=401, detail="Account not found. Check your email or Employee ID, or create an account.")

    stored_hash = user.get("password_hash")
    if stored_hash:
        ok = verify_password(password, stored_hash)
    else:
        # Preset users have no stored password yet: they use the default one
        ok = hmac.compare_digest(password, DEFAULT_PASSWORD)
    if not ok:
        raise HTTPException(status_code=401, detail="Incorrect email, Employee ID or password")

    # Safety net: make sure this user has an employee ID
    if not user.get("employee_id") and "_id" in user:
        try:
            user["employee_id"] = await generate_employee_id()
            await db.users.update_one({"_id": user["_id"]}, {"$set": {"employee_id": user["employee_id"]}})
        except Exception:
            pass

    return {"user": public_user(user)}


@app.get("/api/users")
async def get_users():
    try:
        return await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(500)
    except Exception:
        return DEFAULT_USERS


# ------------------ ADMIN: MANAGE EMPLOYEES ------------------
@app.post("/api/admin/employees")
async def admin_create_employee(data: dict, x_user_email: Optional[str] = Header(None)):
    await require_admin(x_user_email)

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    department = (data.get("department") or "General").strip()
    role = data.get("role") if data.get("role") in ("employee", "admin") else "employee"
    password = data.get("password") or DEFAULT_PASSWORD

    if not name or not email:
        raise HTTPException(status_code=400, detail="Name and email are required")

    try:
        if await db.users.find_one({"email": email}):
            raise HTTPException(status_code=409, detail="An employee with this email already exists")
        user = {
            "name": name,
            "email": email,
            "department": department,
            "role": role,
            "employee_id": await generate_employee_id(),
            "password_hash": hash_password(password),
        }
        await db.users.insert_one(user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    return {"message": "Employee created", "user": public_user(user)}


@app.put("/api/admin/employees/{target_email}")
async def admin_update_employee(target_email: str, data: dict, x_user_email: Optional[str] = Header(None)):
    await require_admin(x_user_email)
    target_email = target_email.lower()

    updates = {}
    if data.get("name"):
        updates["name"] = data["name"].strip()
    if data.get("department") is not None:
        updates["department"] = data["department"].strip() or "General"
    if data.get("role") in ("employee", "admin"):
        updates["role"] = data["role"]
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")

    try:
        result = await db.users.update_one({"email": target_email}, {"$set": updates})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Employee not found")
        if "name" in updates:
            await db.documents.update_many({"owner_email": target_email}, {"$set": {"owner_name": updates["name"]}})
        user = await db.users.find_one({"email": target_email})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    return {"message": "Employee updated", "user": public_user(user)}


@app.delete("/api/admin/employees/{target_email}")
async def admin_delete_employee(target_email: str, x_user_email: Optional[str] = Header(None)):
    requester = await require_admin(x_user_email)
    target_email = target_email.lower()

    if target_email == requester["email"].lower():
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    try:
        result = await db.users.delete_one({"email": target_email})
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found")

    return {"message": "Employee deleted"}


# ------------------ SELF: EDIT MY PROFILE ------------------
@app.put("/api/employee/profile/{target_email}")
async def update_own_profile(target_email: str, data: dict, x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email)
    target_email = target_email.lower()

    if requester.get("role") != "admin" and requester["email"].lower() != target_email:
        raise HTTPException(status_code=403, detail="You can only edit your own profile")

    updates = {}
    name = (data.get("name") or "").strip()
    if name:
        updates["name"] = name
    password = data.get("password") or ""
    if password:
        if len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        updates["password_hash"] = hash_password(password)
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")

    try:
        result = await db.users.update_one({"email": target_email}, {"$set": updates})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        if "name" in updates:
            await db.documents.update_many({"owner_email": target_email}, {"$set": {"owner_name": updates["name"]}})
        user = await db.users.find_one({"email": target_email})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    return {"message": "Profile updated", "user": public_user(user)}


# ============================================================
#                OCR PARSER & DOCUMENT SYSTEM
# ============================================================
def parse_key_values_from_ocr(ocr_text: str) -> dict:
    parsed = {}
    for line in ocr_text.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower().replace(" ", "_")
            v = v.strip()
            if k and v:
                parsed[k] = v

    low = ocr_text.lower()
    if "employee id" in low or "id:" in low:
        m = re.search(r'(?:employee id|id)\s*[:#-]?\s*([a-zA-Z0-9\-_]+)', ocr_text, re.IGNORECASE)
        if m:
            parsed["employee_id"] = m.group(1).strip()
    if "name" in low:
        m = re.search(r'name\s*[:#-]?\s*([a-zA-Z\s]+)', ocr_text, re.IGNORECASE)
        if m and ("employee_id" not in parsed or len(parsed.get("name", "")) < 2):
            parsed["name"] = m.group(1).strip()
    if "department" in low:
        m = re.search(r'department\s*[:#-]?\s*([a-zA-Z\s]+)', ocr_text, re.IGNORECASE)
        if m:
            parsed["department"] = m.group(1).strip()
    return parsed


class DocumentIn(BaseModel):
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    doc_type: str = "Other"
    filename: str = "document"
    image: Optional[str] = ""      # data URL of the uploaded image
    ocr_text: str = ""
    key_values: Optional[dict] = {}


def with_image(docs: list) -> list:
    """Ensure every image is a valid data URL so <img> can display it."""
    for d in docs:
        img = d.get("image") or ""
        if img and not img.startswith(("data:", "http")):
            d["image"] = "data:image/jpeg;base64," + img
    return docs


def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    name = filename.lower()
    try:
        if name.endswith((".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp")):
            return pytesseract.image_to_string(Image.open(io.BytesIO(file_bytes))).strip()
        elif name.endswith(".pdf"):
            pages = convert_from_bytes(file_bytes)
            return "\n--- Page Break ---\n".join(pytesseract.image_to_string(p) for p in pages).strip()
        raise HTTPException(status_code=400, detail="Only PDF and image files are supported")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR processing failed: {e}")


@app.post("/api/documents")
async def upload_document(doc: DocumentIn, x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email)
    is_admin = requester.get("role") == "admin"

    target_email = (doc.owner_email or requester["email"]).lower()
    if not is_admin and target_email != requester["email"].lower():
        raise HTTPException(status_code=403, detail="You can only upload your own documents")

    if len(doc.image or "") > 7_000_000:
        raise HTTPException(status_code=413, detail="Image is too large (max about 5 MB)")

    kv = doc.key_values if doc.key_values else parse_key_values_from_ocr(doc.ocr_text)

    item = {
        "id": uuid.uuid4().hex,
        "owner_email": target_email,
        "owner_name": doc.owner_name or requester.get("name", "N/A"),
        "doc_type": doc.doc_type,
        "filename": doc.filename or "document",
        "image": doc.image or "",
        "ocr_text": doc.ocr_text,
        "key_values": kv,
        "uploaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        await db.documents.insert_one(item)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save document: {e}")

    return {"message": "Document saved", "id": item["id"], "key_values": kv}


@app.get("/api/documents/search")
async def search_documents(q: Optional[str] = Query(None), x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email)
    flt = {}
    if requester.get("role") != "admin":
        flt["owner_email"] = requester["email"].lower()
    if q:
        sq = re.escape(q)
        flt["$or"] = [
            {"ocr_text": {"$regex": sq, "$options": "i"}},
            {"filename": {"$regex": sq, "$options": "i"}},
            {"doc_type": {"$regex": sq, "$options": "i"}},
        ]
    try:
        cur = db.documents.find(flt, {"_id": 0, "file_data": 0}).sort("uploaded_at", -1)
        return with_image(await cur.to_list(length=500))
    except Exception:
        return []


@app.get("/api/documents/mine/{email}")
async def my_documents(email: str, x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email or email)
    if requester.get("role") != "admin" and requester["email"].lower() != email.lower():
        raise HTTPException(status_code=403, detail="Not allowed")
    try:
        cur = db.documents.find({"owner_email": email.lower()}, {"_id": 0, "file_data": 0}).sort("uploaded_at", -1)
        return with_image(await cur.to_list(length=500))
    except Exception:
        return []


@app.get("/api/admin/documents")
async def all_documents(x_user_email: Optional[str] = Header(None)):
    await require_admin(x_user_email)
    try:
        cur = db.documents.find({}, {"_id": 0, "file_data": 0}).sort("uploaded_at", -1)
        return with_image(await cur.to_list(length=2000))
    except Exception:
        return []


@app.delete("/api/documents/{doc_id}")
async def delete_document(doc_id: str, x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email)
    try:
        doc = await db.documents.find_one({"id": doc_id})
    except Exception:
        doc = None
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if requester.get("role") != "admin" and doc["owner_email"] != requester["email"].lower():
        raise HTTPException(status_code=403, detail="Not allowed")
    await db.documents.delete_one({"id": doc_id})
    return {"message": "Document deleted"}


# ============================================================
#              SUPPORT TICKETS  (raised by Mitraa)
# ============================================================
TICKET_STATUSES = ("open", "in_progress", "resolved")
TICKET_CATEGORIES = ("Login or account", "Documents", "HR or payroll", "Technical issue", "Something else")
MAX_OPEN_TICKETS_PER_USER = 10


def public_ticket(t: dict) -> dict:
    return {k: v for k, v in t.items() if k != "_id"}


async def next_ticket_id() -> str:
    doc = await db.counters.find_one_and_update(
        {"_id": "tickets"}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER
    )
    return f"TKT-{doc['seq']:04d}"


@app.post("/api/tickets")
async def create_ticket(data: dict, x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email)

    message = (data.get("message") or "").strip()
    category = data.get("category") if data.get("category") in TICKET_CATEGORIES else "Something else"
    if len(message) < 5:
        raise HTTPException(status_code=400, detail="Please describe the problem in a little more detail")
    if len(message) > 2000:
        raise HTTPException(status_code=400, detail="Message is too long (max 2000 characters)")

    try:
        open_count = await db.tickets.count_documents(
            {"user_email": requester["email"].lower(), "status": {"$ne": "resolved"}}
        )
        if open_count >= MAX_OPEN_TICKETS_PER_USER:
            raise HTTPException(status_code=429, detail="You already have several unresolved tickets. Please wait for the admin to respond.")

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ticket = {
            "ticket_id": await next_ticket_id(),
            "user_email": requester["email"].lower(),
            "user_name": requester.get("name", "User"),
            "employee_id": requester.get("employee_id", ""),
            "department": requester.get("department", "General"),
            "category": category,
            "message": message,
            "status": "open",
            "admin_note": "",
            "created_at": now,
            "updated_at": now,
        }
        await db.tickets.insert_one(ticket)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Could not save the ticket: {e}")

    return {"message": "Ticket raised", "ticket": public_ticket(ticket)}


@app.get("/api/tickets/mine")
async def my_tickets(x_user_email: Optional[str] = Header(None)):
    requester = await get_requester(x_user_email)
    try:
        cur = db.tickets.find({"user_email": requester["email"].lower()}, {"_id": 0}).sort("created_at", -1)
        return await cur.to_list(length=200)
    except Exception:
        return []


@app.get("/api/admin/tickets")
async def all_tickets(x_user_email: Optional[str] = Header(None)):
    await require_admin(x_user_email)
    try:
        cur = db.tickets.find({}, {"_id": 0}).sort("created_at", -1)
        return await cur.to_list(length=1000)
    except Exception:
        return []


@app.put("/api/admin/tickets/{ticket_id}")
async def update_ticket(ticket_id: str, data: dict, x_user_email: Optional[str] = Header(None)):
    admin = await require_admin(x_user_email)

    updates = {}
    if data.get("status") is not None:
        if data["status"] not in TICKET_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        updates["status"] = data["status"]
    if data.get("admin_note") is not None:
        note = str(data["admin_note"]).strip()
        if len(note) > 2000:
            raise HTTPException(status_code=400, detail="Note is too long (max 2000 characters)")
        updates["admin_note"] = note
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")

    updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    updates["handled_by"] = admin["email"].lower()

    try:
        result = await db.tickets.update_one({"ticket_id": ticket_id}, {"$set": updates})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Ticket not found")
        ticket = await db.tickets.find_one({"ticket_id": ticket_id})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    return {"message": "Ticket updated", "ticket": public_ticket(ticket)}


# ============================================================
#                       ANALYTICS
# ============================================================
@app.get("/api/admin/analytics")
async def admin_analytics():
    try:
        users = await db.users.find({}, {"_id": 0, "role": 1, "department": 1}).to_list(1000)
    except Exception:
        users = DEFAULT_USERS

    admins = sum(1 for u in users if u.get("role") == "admin")
    counts = {}
    for u in users:
        dept = (u.get("department") or "General").strip()
        if dept.lower() == "quality assurance":
            dept = "QA"
        counts[dept] = counts.get(dept, 0) + 1

    return {
        "stats": {
            "total_employees": len(users) - admins,
            "total_admins": admins,
            "pending_resets": 0,
            "attendance_rate": "98%",
        },
        "department_distribution": [{"name": k, "value": v} for k, v in counts.items()],
        "weekly_attendance": [
            {"day": "Mon", "active": 6, "remote": 1},
            {"day": "Tue", "active": 7, "remote": 0},
            {"day": "Wed", "active": 7, "remote": 0},
            {"day": "Thu", "active": 5, "remote": 2},
            {"day": "Fri", "active": 6, "remote": 1},
        ],
    }