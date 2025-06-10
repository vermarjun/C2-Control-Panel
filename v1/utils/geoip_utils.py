import os
from pathlib import Path
from typing import Dict, Any
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
from dotenv import load_dotenv

load_dotenv()

# Get absolute path to the GeoLite2 database
BASE_DIR = Path(__file__).resolve().parent.parent
GEOIP_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

class GeoIPManager:
    def __init__(self, db_path: str):
        try:
            self.reader = Reader(db_path)
            print(f"Successfully loaded GeoLite2 database from {db_path}")
        except Exception as e:
            print(f"Warning: Could not load GeoLite2 database from {db_path}: {e}")
            self.reader = None

    async def get_location(self, ip: str) -> Dict[str, Any]:
        """Get location information for an IP address"""
        if not self.reader:
            return self._get_default_location(ip)

        if self._is_local_ip(ip):
            return self._get_default_location(ip)

        try:
            response = self.reader.city(ip)
            return {
                "ip": ip,
                "city": response.city.name or "Unknown",
                "country": response.country.name or "Unknown",
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
                "continent": response.continent.name,
                "country_code": response.country.iso_code,
                "postal_code": response.postal.code if response.postal else None,
                "subdivisions": [sub.name for sub in response.subdivisions] if response.subdivisions else []
            }
        except AddressNotFoundError:
            print(f"Address not found in database: {ip}")
            return self._get_default_location(ip)
        except Exception as e:
            print(f"Error getting location for IP {ip}: {e}")
            return self._get_default_location(ip)

    def _is_local_ip(self, ip: str) -> bool:
        """Check if the IP is a local address"""
        return (
            ip in ("127.0.0.1", "localhost") or
            ip.startswith(("192.168.", "10.", "172."))
        )

    def _get_default_location(self, ip: str) -> Dict[str, Any]:
        """Return default location data"""
        return {
            "ip": ip,
            "city": "Unknown",
            "country": "Unknown",
            "latitude": 0,
            "longitude": 0,
            "timezone": None,
            "continent": None,
            "country_code": None,
            "postal_code": None,
            "subdivisions": []
        }

    def close(self):
        """Close the GeoIP database reader"""
        if self.reader:
            self.reader.close()

# Create a singleton instance
geoip_service = GeoIPManager(GEOIP_DB_PATH) 