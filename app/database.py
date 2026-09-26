import os
from contextlib import asynccontextmanager

from motor.motor_asyncio import AsyncIOMotorClient

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://mongo:27017/?replicaSet=rs0")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "police_db")

# uuidRepresentation="standard" is required (not optional): without it,
# pymongo refuses to encode/decode plain `uuid.UUID` values at all (every
# id/foreign-key field in app/models.py is a UUID), raising
# ConfigurationError the first time any query touches one.
client = AsyncIOMotorClient(MONGODB_URL, uuidRepresentation="standard")
database = client[MONGODB_DB_NAME]


async def init_db() -> None:
    """Register all Document models with Beanie and create their indexes.

    Beanie/Mongo has no separate DDL-migration step: this call creates any
    collection/index that doesn't exist yet and is a no-op for ones that
    already match, so it's safe to run on every startup (dev, test, prod).
    """
    from beanie import init_beanie
    from . import models

    await init_beanie(database=database, document_models=models.DOCUMENT_MODELS)


@asynccontextmanager
async def transaction():
    """
    Multi-document ACID transaction (requires the replica-set deployment
    configured in docker-compose.yml). Used at the handful of call sites
    that write an AuditLog row atomically alongside the business-state
    change that triggered it -- the direct Mongo equivalent of the old
    SQLAlchemy pattern of `db.add(audit_entry)` sharing the same
    not-yet-committed transaction as the surrounding `db.commit()`.

    Usage:
        async with database.transaction() as session:
            await some_doc.save(session=session)
            await log_action(..., session=session)
    """
    async with await client.start_session() as session:
        async with session.start_transaction():
            yield session
