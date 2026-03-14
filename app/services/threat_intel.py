import json
import logging
import sqlite3
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self, cache_file: str = "data/threat_intel_cache.db"):
        self.cache_file = cache_file
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS intel_lookups (
                        ip_address TEXT PRIMARY KEY,
                        score INTEGER,
                        tags TEXT,
                        provider TEXT,
                        timestamp REAL
                    )
                ''')
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize Threat Intel Cache DB: {e}")

    def get_intel_for_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Retrieves threat intelligence for an IP address.
        Since we want to avoid requiring API keys from the user, this is a local mock
        with simulated latency and cached responses.
        Returns a dict: {"score": int (0-100), "tags": list[str], "provider": str}
        """
        if not ip_address:
            return None

        # Check cache
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT score, tags, provider, timestamp FROM intel_lookups WHERE ip_address = ?', (ip_address,))
                row = cursor.fetchone()
                if row:
                    # Cache TTL is 24 hours
                    if time.time() - row[3] < 86400:
                        return {
                            "score": row[0],
                            "tags": json.loads(row[1]),
                            "provider": row[2]
                        }
        except Exception as e:
            logger.error(f"Error reading Threat Intel DB: {e}")

        # Stub Integration Logic 
        return self._fetch_mock_intel(ip_address)

    def _fetch_mock_intel(self, ip_address: str) -> Dict:
        """
        Simulates an API request to a Third-Party provider like AbuseIPDB or VirusTotal.
        Uses deterministic characteristics of the IP to generate realistic intel without network overhead.
        """
        # Hash the IP address to create deterministic "randomness"
        ip_hash = sum(ord(c) for c in ip_address)
        
        # Determine reputation score based on IP hash
        score = (ip_hash * 17) % 100
        
        # Tags
        possible_tags = ["Tor Exit Node", "Known Scanner", "Botnet C&C", "Spam Relay", "Brute-Forcer", "VPN"]
        tags = []
        if score > 50:
            tags.append(possible_tags[ip_hash % len(possible_tags)])
            tags.append(possible_tags[(ip_hash * 3) % len(possible_tags)])
            tags = list(set(tags))  # Deduplicate

        provider = "Mock-Threat-Intel"

        # Cache the result
        try:
            with sqlite3.connect(self.cache_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO intel_lookups (ip_address, score, tags, provider, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip_address, score, json.dumps(tags), provider, time.time()))
                conn.commit()
        except Exception as e:
            logger.error(f"Error writing to Threat Intel cache: {e}")

        return {
            "score": score,
            "tags": tags,
            "provider": provider
        }

# Singleton instance
threat_intel = ThreatIntelService()
