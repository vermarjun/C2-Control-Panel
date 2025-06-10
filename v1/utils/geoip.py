import os
from pathlib import Path
import geoip2.database
import geoip2.errors
from typing import Dict, Any

class GeoIPManager:
    def __init__(self, db_path: str):
        """Initialize the GeoIP manager with the database path."""
        self.db_path = db_path
        try:
            self.reader = geoip2.database.Reader(db_path)
            print(f"Successfully loaded GeoLite2 database from {db_path}")
        except Exception as e:
            print(f"Warning: Could not load GeoLite2 database: {e}")
            self.reader = None

    async def get_location(self, ip: str) -> Dict[str, Any]:
        """Get location data for an IP address."""
        if not self.reader:
            return self._get_default_location()

        try:
            if self._is_local_ip(ip):
                return self._get_default_location()

            response = self.reader.city(ip)
            return {
                "city": response.city.name or "Unknown",
                "country": response.country.name or "Unknown",
                "latitude": response.location.latitude or 0,
                "longitude": response.location.longitude or 0,
                "timezone": response.location.time_zone or "UTC"
            }
        except geoip2.errors.AddressNotFoundError:
            return self._get_default_location()
        except Exception as e:
            print(f"Error getting location for IP {ip}: {e}")
            return self._get_default_location()

    def _is_local_ip(self, ip: str) -> bool:
        """Check if the IP is a local address."""
        return ip in ("127.0.0.1", "localhost", "::1") or ip.startswith(("192.168.", "10.", "172.16."))

    def _get_default_location(self) -> Dict[str, Any]:
        """Return default location data."""
        return {
            "city": "Unknown",
            "country": "Unknown",
            "latitude": 0,
            "longitude": 0,
            "timezone": "UTC"
        }

    def close(self):
        """Close the database reader."""
        if self.reader:
            self.reader.close() 