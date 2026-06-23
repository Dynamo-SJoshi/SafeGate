import json
import urllib.request
import urllib.error

def get_location_from_ip(ip_address: str) -> str:
    """
    Looks up geolocation details for the given IP address using ip-api.com.
    Returns format: 'City, Region (Country)' or 'Local Development' or 'Unknown Location'.
    """
    if not ip_address or ip_address in ("127.0.0.1", "localhost", "unknown", "::1"):
        return "Local Development"
        
    try:
        # Query free ip-api JSON service (limit 45 requests/min)
        url = f"http://ip-api.com/json/{ip_address}"
        req = urllib.request.Request(url, headers={"User-Agent": "SafeGate-IP-Locator"})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success":
                city = data.get("city") or "Unknown City"
                region = data.get("regionName") or "Unknown Region"
                country = data.get("country") or "Unknown Country"
                return f"{city}, {region} ({country})"
            else:
                return "Unknown Location"
    except Exception as exc:
        print(f"Failed to geolocate IP {ip_address}: {exc}")
        return "Unknown Location"
