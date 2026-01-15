from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Query, Depends
from uuid import UUID, uuid4
from fastapi.responses import HTMLResponse
import uvicorn
import aiosqlite
import os
import bcrypt
from jwt import encode, decode
from jwt.exceptions import InvalidTokenError

# --- Конфигурация ---
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 48 * 60  # 48 часов

DB_PATH = os.getenv("DB_PATH", "ads.db")

app = FastAPI()

# --- Модели данных ---
class Advertisement(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10, max_length=1000)
    price: float = Field(..., gt=0)
    author: Optional[str] = Field(None, min_length=2, max_length=100)  # ← теперь опционально
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    username: str = Field(..., min_length=3, max_length=50)
    role: str = Field(default="user", pattern="^(user|admin)$")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    role: str = Field(default="user", pattern="^(user|admin)$")
    password: str = Field(..., min_length=6)

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- JWT ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        exp: int = payload.get("exp")
        if datetime.fromtimestamp(exp) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Token expired")
        return {"username": username, "role": role}
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user_optional(authorization: str = None):
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    return verify_token(token)

def check_permission(current_user: dict, user_id: UUID, ad_author: str = None, action: str = "read"):
    if not current_user:
        if action in ["create", "update", "delete"]:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return True  # read allowed

    if current_user["role"] == "admin":
        return True

    if action == "update" or action == "delete":
        if ad_author and ad_author != current_user["username"]:
            raise HTTPException(status_code=403, detail="Not allowed to modify another user's ad")
        if str(user_id) and str(user_id) != str(current_user["user_id"]):
            raise HTTPException(status_code=403, detail="Not allowed to modify another user")

    return True

# --- База данных ---
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS advertisements (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL,
                author TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
        """)
        await db.commit()

# --- Функции для пользователей ---
async def create_user_db(user: User, password_hash: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(user.id), user.username, password_hash, user.role, user.created_at.isoformat())
        )
        await db.commit()

async def get_user_by_username_db(username: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
            (username,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "id": UUID(row[0]),
            "username": row[1],
            "password_hash": row[2],
            "role": row[3],
            "created_at": datetime.fromisoformat(row[4])
        }

async def get_user_by_id_db(user_id: UUID):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?",
            (str(user_id),)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return User(
            id=UUID(row[0]),
            username=row[1],
            role=row[2],
            created_at=datetime.fromisoformat(row[3])
        )

async def update_user_db(user_id: UUID, updated_data: dict):
    fields = []
    values = []

    for field, value in updated_data.items():
        if field in ["username", "role"] and value is not None:
            fields.append(f"{field} = ?")
            values.append(value)

    if not fields:
        return

    values.append(str(user_id))

    query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(query, values)
        await db.commit()

async def delete_user_db(user_id: UUID):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE id = ?", (str(user_id),))
        await db.commit()

# --- Функции для объявлений ---
async def create_ad_db(ad: Advertisement):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO advertisements (id, title, description, price, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(ad.id), ad.title, ad.description, ad.price, ad.author, ad.created_at.isoformat(), ad.updated_at.isoformat() if ad.updated_at else None)
        )
        await db.commit()

async def get_ad_by_id_db(ad_id: UUID) -> Optional[Advertisement]:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT id, title, description, price, author, created_at, updated_at FROM advertisements WHERE id = ?",
            (str(ad_id),)
        )
        row = await cursor.fetchone()
        if not row:
            return None

        return Advertisement(
            id=UUID(row[0]),
            title=row[1],
            description=row[2],
            price=row[3],
            author=row[4],
            created_at=datetime.fromisoformat(row[5]),
            updated_at=datetime.fromisoformat(row[6]) if row[6] else None
        )

async def update_ad_db(ad_id: UUID, updated_data: dict):
    fields = []
    values = []

    for field, value in updated_data.items():
        if field in ["title", "description", "price", "author"] and value is not None:
            fields.append(f"{field} = ?")
            values.append(value)

    if not fields:
        return

    fields.append("updated_at = ?")
    values.append(datetime.utcnow().isoformat())
    values.append(str(ad_id))

    query = f"UPDATE advertisements SET {', '.join(fields)} WHERE id = ?"

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(query, values)
        await db.commit()

async def delete_ad_db(ad_id: UUID):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM advertisements WHERE id = ?", (str(ad_id),))
        await db.commit()

async def search_ads_db(
    title: Optional[str] = None,
    author: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None
):
    query = "SELECT id, title, description, price, author, created_at, updated_at FROM advertisements WHERE 1=1"
    params = []

    if title:
        query += " AND title LIKE ?"
        params.append(f"%{title}%")
    if author:
        query += " AND author LIKE ?"
        params.append(f"%{author}%")
    if min_price is not None:
        query += " AND price >= ?"
        params.append(min_price)
    if max_price is not None:
        query += " AND price <= ?"
        params.append(max_price)

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()

        results = []
        for row in rows:
            results.append(
                Advertisement(
                    id=UUID(row[0]),
                    title=row[1],
                    description=row[2],
                    price=row[3],
                    author=row[4],
                    created_at=datetime.fromisoformat(row[5]),
                    updated_at=datetime.fromisoformat(row[6]) if row[6] else None
                )
            )
        return results

# --- Роуты ---
@app.on_event("startup")
async def startup_event():
    await init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>API Объявлений</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #2e6c80; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>API Объявлений (Купля/Продажа)</h1>
        <p>Доступные HTTP-запросы:</p>
        <table>
          <tr>
            <th>Метод</th>
            <th>URL</th>
            <th>Описание</th>
            <th>Требуется токен?</th>
          </tr>
          <tr>
            <td>POST</td>
            <td>/login</td>
            <td>Вход (получение токена)</td>
            <td>❌</td>
          </tr>
          <tr>
            <td>POST</td>
            <td>/user</td>
            <td>Создать пользователя</td>
            <td>❌</td>
          </tr>
          <tr>
            <td>GET</td>
            <td>/user/{id}</td>
            <td>Получить пользователя по ID</td>
            <td>❌</td>
          </tr>
          <tr>
            <td>GET</td>
            <td>/advertisement/{id}</td>
            <td>Получить объявление по ID</td>
            <td>❌</td>
          </tr>
          <tr>
            <td>GET</td>
            <td>/advertisement?title=...&author=...&min_price=...&max_price=...</td>
            <td>Поиск объявлений</td>
            <td>❌</td>
          </tr>
          <tr>
            <td>PATCH</td>
            <td>/user/{id}</td>
            <td>Обновить пользователя (только свой)</td>
            <td>✅ (user)</td>
          </tr>
          <tr>
            <td>DELETE</td>
            <td>/user/{id}</td>
            <td>Удалить пользователя (только себя)</td>
            <td>✅ (user)</td>
          </tr>
          <tr>
            <td>POST</td>
            <td>/advertisement</td>
            <td>Создать объявление</td>
            <td>✅ (user)</td>
          </tr>
          <tr>
            <td>PATCH</td>
            <td>/advertisement/{id}</td>
            <td>Обновить объявление (только своё)</td>
            <td>✅ (user)</td>
          </tr>
          <tr>
            <td>DELETE</td>
            <td>/advertisement/{id}</td>
            <td>Удалить объявление (только своё)</td>
            <td>✅ (user)</td>
          </tr>
        </table>
    </body>
    </html>
    """
    return html_content

# --- Авторизация ---
@app.post("/login", response_model=Token)
async def login(request: LoginRequest):
    user_record = await get_user_by_username_db(request.username)
    if not user_record or not bcrypt.checkpw(request.password.encode(), user_record["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token_data = {
        "sub": user_record["username"],
        "role": user_record["role"]
    }
    token = create_access_token(token_data)
    return {"access_token": token, "token_type": "bearer"}

# --- Пользователи ---
@app.post("/user", response_model=User)
async def create_user(user_create: UserCreate):
    existing_user = await get_user_by_username_db(user_create.username)
    if existing_user:
        raise HTTPException(status_code=409, detail="User with this username already exists")

    hashed_password = bcrypt.hashpw(user_create.password.encode(), bcrypt.gensalt()).decode()

    user = User(
        id=uuid4(),
        username=user_create.username,
        role=user_create.role,
        created_at=datetime.utcnow()
    )

    await create_user_db(user, hashed_password)
    return user

@app.get("/user/{user_id}", response_model=User)
async def get_user(user_id: UUID):
    user = await get_user_by_id_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.patch("/user/{user_id}", response_model=User)
async def update_user(user_id: UUID, updated_data: dict, current_user: dict = Depends(get_current_user_optional)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if current_user["role"] != "admin":
        if str(user_id) != current_user["username"]:  # исправлено: сравниваем с username
            raise HTTPException(status_code=403, detail="Not allowed to update another user")

    await update_user_db(user_id, updated_data)
    updated_user = await get_user_by_id_db(user_id)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user

@app.delete("/user/{user_id}")
async def delete_user(user_id: UUID, current_user: dict = Depends(get_current_user_optional)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if current_user["role"] != "admin":
        if str(user_id) != current_user["username"]:
            raise HTTPException(status_code=403, detail="Not allowed to delete another user")

    await delete_user_db(user_id)
    return {"message": "User deleted"}

# --- Объявления ---
@app.post("/advertisement", response_model=Advertisement)
async def create_ad(ad: Advertisement, current_user: dict = Depends(get_current_user_optional)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    ad.author = current_user["username"]
    ad.id = uuid4()
    ad.created_at = datetime.utcnow()
    ad.updated_at = None
    await create_ad_db(ad)
    return ad

@app.get("/advertisement/{advertisement_id}", response_model=Advertisement)
async def get_ad_by_id(advertisement_id: UUID):
    ad = await get_ad_by_id_db(advertisement_id)
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")
    return ad

@app.patch("/advertisement/{advertisement_id}", response_model=Advertisement)
async def update_ad(advertisement_id: UUID, updated_data: dict, current_user: dict = Depends(get_current_user_optional)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    ad = await get_ad_by_id_db(advertisement_id)
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    if current_user["role"] != "admin":
        if ad.author != current_user["username"]:
            raise HTTPException(status_code=403, detail="Not allowed to update another user's ad")

    await update_ad_db(advertisement_id, updated_data)
    updated_ad = await get_ad_by_id_db(advertisement_id)
    return updated_ad

@app.delete("/advertisement/{advertisement_id}")
async def delete_ad(advertisement_id: UUID, current_user: dict = Depends(get_current_user_optional)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    ad = await get_ad_by_id_db(advertisement_id)
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    if current_user["role"] != "admin":
        if ad.author != current_user["username"]:
            raise HTTPException(status_code=403, detail="Not allowed to delete another user's ad")

    await delete_ad_db(advertisement_id)
    return {"message": "Advertisement deleted"}

@app.get("/advertisement")
async def search_ads(
    title: Optional[str] = Query(None, min_length=1),
    author: Optional[str] = Query(None, min_length=1),
    min_price: Optional[float] = Query(None, ge=0),
    max_price: Optional[float] = Query(None, ge=0)
):
    results = await search_ads_db(title=title, author=author, min_price=min_price, max_price=max_price)
    return results

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)