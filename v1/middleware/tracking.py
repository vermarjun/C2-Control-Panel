from fastapi import Request
from datetime import datetime
from typing import Set
from utils.geoip import GeoIPManager
from database import update_user_activity, update_user_location, log_api_call

IGNORED_ENDPOINTS: Set[str] = {
    "/api/user/activity",
    "/api/user/page-visit",
    "/auth/verify",
    "/health",
}

class TrackingMiddleware:
    def __init__(self, geoip_manager: GeoIPManager):
        self.geoip_manager = geoip_manager

    async def process_request(self, request: Request, username: str):
        if request.url.path in IGNORED_ENDPOINTS:
            return

        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "Unknown")
        device_fingerprint = request.headers.get("x-device-fingerprint")

        # Get location data
        location_data = await self.geoip_manager.get_location(client_ip)

        # Update user activity
        await update_user_activity(
            username=username,
            ip=client_ip,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint
        )

        # Update location if coordinates are available
        if location_data["latitude"] != 0 or location_data["longitude"] != 0:
            await update_user_location(
                username=username,
                ip=client_ip,
                city=location_data["city"],
                country=location_data["country"],
                latitude=location_data["latitude"],
                longitude=location_data["longitude"]
            )

        # Log API call
        await log_api_call(
            username=username,
            route=str(request.url.path),
            method=request.method
        )