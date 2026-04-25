"""
Geo Velocity Analyzer — detects impossible geographic transitions.

GeoVelocityAnalyzer and the _haversine helper live here. Previously
GeoVelocityAnalyzer was defined in timing.py and re-exported from this
file, which meant check_and_update() called time.time() via timing.py's
import — a confusing indirection and a maintenance trap. Both classes now
live in their natural homes.
"""
import math
import time
import logging

logger = logging.getLogger(__name__)

MAX_HUMAN_SPEED_KMH = 1000.0  # max commercial aircraft speed
TOLERANCE_KM = 50.0            # small buffer for GeoIP inaccuracy


class GeoVelocityAnalyzer:
    """
    Tracks the last known geo location per session.
    Raises a flag if the location changes faster than physically possible.
    """
    def __init__(self):
        # session_id -> (lat, lon, timestamp)
        self.session_locations: dict[str, tuple[float, float, float]] = {}

    def check_and_update(self, session_id: str, lat: float, lon: float) -> bool:
        """
        Returns True if the geo velocity is IMPOSSIBLE (bot indicator).
        Updates the stored location for future checks regardless.
        """
        now = time.time()

        if session_id in self.session_locations:
            prev_lat, prev_lon, prev_ts = self.session_locations[session_id]
            elapsed_hours = (now - prev_ts) / 3600.0

            if elapsed_hours > 0:
                dist_km = _haversine(prev_lat, prev_lon, lat, lon)
                speed_kmh = dist_km / elapsed_hours
                max_possible_km = MAX_HUMAN_SPEED_KMH * elapsed_hours + TOLERANCE_KM

                if dist_km > max_possible_km:
                    logger.warning(
                        f"Geo velocity violation for session {session_id[:8]}...: "
                        f"{dist_km:.0f}km in {elapsed_hours * 3600:.0f}s "
                        f"(speed={speed_kmh:.0f}km/h, max={MAX_HUMAN_SPEED_KMH}km/h)"
                    )
                    self.session_locations[session_id] = (lat, lon, now)
                    return True

        self.session_locations[session_id] = (lat, lon, now)
        return False

    def cleanup_old(self, max_age_seconds: float = 3600.0):
        """Remove stale session records to prevent unbounded memory growth."""
        now = time.time()
        cutoff = now - max_age_seconds
        self.session_locations = {
            sid: (lat, lon, ts)
            for sid, (lat, lon, ts) in self.session_locations.items()
            if ts > cutoff
        }


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2))
         * math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
