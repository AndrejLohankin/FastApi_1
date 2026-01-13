from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Query
from uuid import UUID, uuid4
from fastapi.responses import HTMLResponse
import uvicorn
import aiosqlite
import os


DB_PATH = os.getenv("DB_PATH", "ads.db")

app = FastAPI()

# Модель данных
class Advertisement(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10, max_length=1000)
    price: float = Field(..., gt=0)
    author: str = Field(..., min_length=2, max_length=100)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


async def init_db():
    """Создаёт таблицу, если её нет"""
    async with aiosqlite.connect(DB_PATH) as db:
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

async def create_ad_db(ad: Advertisement):
    """Сохраняет объявление в БД"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO advertisements (id, title, description, price, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(ad.id), ad.title, ad.description, ad.price, ad.author, ad.created_at.isoformat(), ad.updated_at.isoformat() if ad.updated_at else None)
        )
        await db.commit()

async def get_ad_by_id_db(ad_id: UUID) -> Optional[Advertisement]:
    """Получает объявление по ID из БД"""
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
    """Обновляет объявление в БД"""
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
    """Удаляет объявление из БД"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM advertisements WHERE id = ?", (str(ad_id),))
        await db.commit()

async def search_ads_db(
    title: Optional[str] = None,
    author: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None
):
    """Поиск объявлений по параметрам"""
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
            <th>Пример тела (JSON)</th>
          </tr>
          <tr>
            <td>POST</td>
            <td>/advertisement</td>
            <td>Создать новое объявление</td>
            <td>{"title": "...", "description": "...", "price": 100, "author": "..."}</td>
          </tr>
          <tr>
            <td>GET</td>
            <td>/advertisement/{id}</td>
            <td>Получить объявление по ID</td>
            <td>—</td>
          </tr>
          <tr>
            <td>PATCH</td>
            <td>/advertisement/{id}</td>
            <td>Обновить объявление (частично)</td>
            <td>{"title": "...", "price": 90}</td>
          </tr>
          <tr>
            <td>DELETE</td>
            <td>/advertisement/{id}</td>
            <td>Удалить объявление</td>
            <td>—</td>
          </tr>
          <tr>
            <td>GET</td>
            <td>/advertisement?title=...&author=...&min_price=...&max_price=...</td>
            <td>Поиск объявлений по параметрам</td>
            <td>—</td>
          </tr>
        </table>

        <p><strong>Примечание:</strong> замените <code>{id}</code> на UUID объявления (например: <code>c94c5c20-3ca0-4792-a334-e10bc43161d5</code>)</p>
    </body>
    </html>
    """
    return html_content

@app.post("/advertisement", response_model=Advertisement)
async def create_ad(ad: Advertisement):
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
async def update_ad(advertisement_id: UUID, updated_data: dict):
    ad = await get_ad_by_id_db(advertisement_id)
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    await update_ad_db(advertisement_id, updated_data)
    updated_ad = await get_ad_by_id_db(advertisement_id)
    return updated_ad

@app.delete("/advertisement/{advertisement_id}")
async def delete_ad(advertisement_id: UUID):
    ad = await get_ad_by_id_db(advertisement_id)
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found")
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