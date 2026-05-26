import os

from loguru import logger
from config import settings
from database.memory_db import InMemoryDatabase

db = InMemoryDatabase()


async def connect_to_mongo():
    """Initialize the database and seed IOCs. No external MongoDB needed."""
    logger.info(f"Using in-memory database (no MongoDB required)")
    await seed_iocs()


async def close_mongo_connection():
    """No-op for in-memory database."""
    logger.info("In-memory database shutdown (no-op)")


async def get_database():
    return db


async def seed_iocs():
    """Seed IOC data from text files into the in-memory database."""
    existing_count = await db.iocs.count_documents({})
    if existing_count > 0:
        logger.info(f"IOC collection already seeded ({existing_count} documents)")
        return

    ioc_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), settings.IOC_DIR)
    if not os.path.isdir(ioc_dir):
        logger.warning(f"IOC directory not found: {ioc_dir}")
        return

    mapping = {
        "malicious_ips.txt": ("ip", "malicious_ip"),
        "malicious_domains.txt": ("domain", "malicious_domain"),
        "malware_hashes.txt": ("hash", "malware_hash"),
    }

    inserted = 0
    for filename, (ioc_type, threat_type) in mapping.items():
        filepath = os.path.join(ioc_dir, filename)
        if not os.path.isfile(filepath):
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "#" in line:
                    value = line.split("#")[0].strip()
                    comment = line.split("#", 1)[1].strip()
                else:
                    value = line
                    comment = ""

                if not value:
                    continue

                try:
                    doc = {
                        "type": ioc_type,
                        "value": value,
                        "threat_type": threat_type,
                        "source": "seed_file",
                        "tags": [comment] if comment else [],
                        "status": "active",
                        "confidence": 0.8,
                    }
                    existing = await db.iocs.find_one({"value": value})
                    if not existing:
                        await db.iocs.insert_one(doc)
                        inserted += 1
                except Exception as e:
                    logger.warning(f"Failed to insert IOC {value}: {e}")

    logger.info(f"Seeded {inserted} IOCs from seed files")
