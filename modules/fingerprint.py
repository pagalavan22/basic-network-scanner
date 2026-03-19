import subprocess
import re

def get_os(ip):
    """Guess OS based on TTL value from ping response."""
    try:
        # Run ping command (Windows style)
        output = subprocess.check_output(
            ["ping", "-n", "1", ip],
            stderr=subprocess.DEVNULL,
            timeout=5
        ).decode(errors="ignore")

        # Extract TTL value using regex
        match = re.search(r"TTL[=\s](\d+)", output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))

            # Guess OS based on TTL
            if ttl <= 64:
                return f"Linux / macOS (TTL={ttl})"
            elif ttl <= 128:
                return f"Windows (TTL={ttl})"
            else:
                return f"Network device (TTL={ttl})"
        else:
            return "Host unreachable (no ping response)"

    except subprocess.TimeoutExpired:
        return "Ping timed out"
    except Exception as e:
        return f"Error: {e}"