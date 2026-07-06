import os
import sqlite3

import requests

# Basic file-based cache to avoid ratelimiting the free public API
CACHE_DB_PATH = "data/geoip_cache.db"

def init_db():
    os.makedirs(os.path.dirname(CACHE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS geoip (
            ip_address TEXT PRIMARY KEY,
            lat REAL,
            lon REAL,
            country TEXT,
            city TEXT
        )
    ''')
    conn.commit()
    conn.close()

class GeoIPService:
    def __init__(self):
        init_db()
        # Internal memory cache for ultra-fast repeated lookups in the same loop
        self._memory_cache = {}

    def get_location(self, ip_address: str) -> dict | None:
        # 1. Check local memory
        if ip_address in self._memory_cache:
            return self._memory_cache[ip_address]

        # 2. Check SQLite persistent cache
        conn = sqlite3.connect(CACHE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT lat, lon, country, city FROM geoip WHERE ip_address=?", (ip_address,))
        row = cursor.fetchone()

        if row:
            conn.close()
            result = {"lat": row[0], "lon": row[1], "country": row[2], "city": row[3]}
            self._memory_cache[ip_address] = result
            return result

        # 3. If not cached, call public API (ip-api.com)
        # Note: ip-api limits to 45 requests per minute for the free tier.
        # Since we rely on a dataset with repeated IPs, our cache protects us quickly.
        try:
            # Don't resolve local/private IPs
            if ip_address.startswith("10.") or ip_address.startswith("192.168.") or ip_address.startswith("172."):
                return None

            response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,lat,lon,country,city", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result = {
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "country": data.get("country"),
                        "city": data.get("city")
                    }

                    # Store in DB
                    cursor.execute(
                        "INSERT INTO geoip (ip_address, lat, lon, country, city) VALUES (?, ?, ?, ?, ?)",
                        (ip_address, result["lat"], result["lon"], result["country"], result["city"])
                    )
                    conn.commit()

                    self._memory_cache[ip_address] = result
                    conn.close()
                    return result
        except requests.RequestException:
            pass # Network error or rate limiting

        conn.close()
        return None

# Global Singleton
geoip_engine = GeoIPService()
