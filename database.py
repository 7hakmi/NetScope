import sqlite3

from datetime import datetime



DATABASE_FILE = "network_monitor.db"





def get_connection():

    connection = sqlite3.connect(DATABASE_FILE, timeout=10)

    connection.row_factory = sqlite3.Row

    return connection





def init_database():

    connection = get_connection()

    cursor = connection.cursor()



    cursor.execute("""

        CREATE TABLE IF NOT EXISTS devices (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            ip TEXT NOT NULL UNIQUE,

            removable INTEGER DEFAULT 1,

            first_seen TEXT,

            last_seen TEXT

        )

    """)



    cursor.execute("""

        CREATE TABLE IF NOT EXISTS monitoring_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_ip TEXT NOT NULL,

            status TEXT NOT NULL,

            latency REAL,

            packet_loss REAL,

            checked_at TEXT NOT NULL

        )

    """)



    cursor.execute("""

        CREATE TABLE IF NOT EXISTS events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_type TEXT NOT NULL,

            title TEXT NOT NULL,

            message TEXT NOT NULL,

            severity TEXT NOT NULL,

            created_at TEXT NOT NULL

        )

    """)




    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            device_name TEXT,
            severity TEXT NOT NULL DEFAULT 'Critical',
            status TEXT NOT NULL DEFAULT 'Active',
            started_at TEXT NOT NULL,
            resolved_at TEXT,
            duration_seconds INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_device_status
        ON incidents (device_ip, status)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_started_at
        ON incidents (started_at)
    """)

    cursor.execute("""

        CREATE INDEX IF NOT EXISTS idx_monitoring_history_device_time

        ON monitoring_history (device_ip, checked_at)

    """)



    cursor.execute("""

        CREATE INDEX IF NOT EXISTS idx_events_created_at

        ON events (created_at)

    """)



    connection.commit()

    connection.close()





def save_monitoring_result(device_ip, status, latency, packet_loss):

    connection = get_connection()



    try:

        connection.execute("""

            INSERT INTO monitoring_history (

                device_ip,

                status,

                latency,

                packet_loss,

                checked_at

            )

            VALUES (?, ?, ?, ?, ?)

        """, (

            device_ip,

            status,

            latency,

            packet_loss,

            datetime.now().isoformat(timespec="seconds")

        ))



        connection.commit()



    finally:

        connection.close()





def calculate_uptime(device_ip):

    connection = get_connection()



    try:

        result = connection.execute("""

            SELECT

                COUNT(*) AS total_checks,

                SUM(

                    CASE

                        WHEN status = 'Online' THEN 1

                        ELSE 0

                    END

                ) AS online_checks

            FROM monitoring_history

            WHERE device_ip = ?

        """, (device_ip,)).fetchone()



    finally:

        connection.close()



    total_checks = result["total_checks"] or 0

    online_checks = result["online_checks"] or 0



    if total_checks == 0:

        return 0



    return round(

        (online_checks / total_checks) * 100,

        2

    )





def get_device_statistics(device_ip):

    connection = get_connection()



    try:

        result = connection.execute("""

            SELECT

                COUNT(*) AS total_checks,



                AVG(

                    CASE

                        WHEN latency IS NOT NULL

                        THEN latency

                    END

                ) AS average_latency,



                MIN(

                    CASE

                        WHEN latency IS NOT NULL

                        THEN latency

                    END

                ) AS minimum_latency,



                MAX(

                    CASE

                        WHEN latency IS NOT NULL

                        THEN latency

                    END

                ) AS maximum_latency,



                AVG(packet_loss)

                    AS average_packet_loss



            FROM monitoring_history



            WHERE device_ip = ?

        """, (device_ip,)).fetchone()



    finally:

        connection.close()



    return {

        "total_checks":

            result["total_checks"] or 0,



        "average_latency":

            round(

                result["average_latency"] or 0,

                1

            ),



        "minimum_latency":

            round(

                result["minimum_latency"] or 0,

                1

            ),



        "maximum_latency":

            round(

                result["maximum_latency"] or 0,

                1

            ),



        "average_packet_loss":

            round(

                result["average_packet_loss"] or 0,

                1

            )

    }





def get_recent_history(device_ip, limit=50):

    connection = get_connection()



    try:

        rows = connection.execute("""

            SELECT

                status,

                latency,

                packet_loss,

                checked_at



            FROM monitoring_history



            WHERE device_ip = ?



            ORDER BY id DESC



            LIMIT ?

        """, (

            device_ip,

            limit

        )).fetchall()



    finally:

        connection.close()



    return [

        dict(row)

        for row in reversed(rows)

    ]





def save_event(

    event_type,

    title,

    message,

    severity

):

    connection = get_connection()



    try:

        connection.execute("""

            INSERT INTO events (

                event_type,

                title,

                message,

                severity,

                created_at

            )

            VALUES (?, ?, ?, ?, ?)

        """, (

            event_type,

            title,

            message,

            severity,

            datetime.now().isoformat(

                timespec="seconds"

            )

        ))



        connection.commit()



    finally:

        connection.close()





def get_events(limit=100):

    connection = get_connection()



    try:

        rows = connection.execute("""

            SELECT

                id,

                event_type,

                title,

                message,

                severity,

                created_at



            FROM events



            ORDER BY id DESC



            LIMIT ?

        """, (limit,)).fetchall()



    finally:

        connection.close()



    events = []



    for row in rows:

        item = dict(row)



        try:

            created_at = datetime.fromisoformat(

                item["created_at"]

            )



            date_value = created_at.strftime(

                "%Y-%m-%d"

            )



            time_value = created_at.strftime(

                "%H:%M:%S"

            )



        except (TypeError, ValueError):

            date_value = ""

            time_value = ""



        events.append({

            "id": str(item["id"]),

            "type": item["event_type"],

            "title": item["title"],

            "message": item["message"],

            "severity": item["severity"],

            "date": date_value,

            "time": time_value,

            "created_at": item["created_at"]

        })



    return events





def clear_events():

    connection = get_connection()



    try:

        connection.execute(

            "DELETE FROM events"

        )



        connection.commit()



    finally:

        connection.close()




def open_incident(device_ip, device_name=None, severity="Critical"):
    """Create one active incident per device without duplicates."""
    connection = get_connection()
    try:
        existing = connection.execute("""
            SELECT id FROM incidents
            WHERE device_ip = ? AND status = 'Active'
            ORDER BY id DESC LIMIT 1
        """, (device_ip,)).fetchone()

        if existing:
            return existing["id"]

        cursor = connection.execute("""
            INSERT INTO incidents (
                device_ip, device_name, severity, status,
                started_at, resolved_at, duration_seconds
            )
            VALUES (?, ?, ?, 'Active', ?, NULL, 0)
        """, (
            device_ip,
            device_name,
            severity,
            datetime.now().isoformat(timespec="seconds")
        ))
        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def resolve_incident(device_ip):
    """Resolve the newest active incident and calculate downtime."""
    connection = get_connection()
    try:
        incident = connection.execute("""
            SELECT id, started_at FROM incidents
            WHERE device_ip = ? AND status = 'Active'
            ORDER BY id DESC LIMIT 1
        """, (device_ip,)).fetchone()

        if not incident:
            return None

        resolved_at = datetime.now()
        try:
            started_at = datetime.fromisoformat(incident["started_at"])
            duration_seconds = max(
                0, int((resolved_at - started_at).total_seconds())
            )
        except (TypeError, ValueError):
            duration_seconds = 0

        connection.execute("""
            UPDATE incidents
            SET status = 'Resolved',
                resolved_at = ?,
                duration_seconds = ?
            WHERE id = ?
        """, (
            resolved_at.isoformat(timespec="seconds"),
            duration_seconds,
            incident["id"]
        ))
        connection.commit()
        return incident["id"]
    finally:
        connection.close()


def get_active_incident(device_ip):
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT id, device_ip, device_name, severity, status,
                   started_at, resolved_at, duration_seconds
            FROM incidents
            WHERE device_ip = ? AND status = 'Active'
            ORDER BY id DESC LIMIT 1
        """, (device_ip,)).fetchone()
    finally:
        connection.close()

    return dict(row) if row else None


def get_incidents(limit=100, status=None):
    """Return incidents newest first."""
    connection = get_connection()
    try:
        if status in {"Active", "Resolved"}:
            rows = connection.execute("""
                SELECT id, device_ip, device_name, severity, status,
                       started_at, resolved_at, duration_seconds
                FROM incidents
                WHERE status = ?
                ORDER BY id DESC LIMIT ?
            """, (status, limit)).fetchall()
        else:
            rows = connection.execute("""
                SELECT id, device_ip, device_name, severity, status,
                       started_at, resolved_at, duration_seconds
                FROM incidents
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
    finally:
        connection.close()

    now = datetime.now()
    result = []
    for row in rows:
        item = dict(row)
        if item["status"] == "Active":
            try:
                started_at = datetime.fromisoformat(item["started_at"])
                item["duration_seconds"] = max(
                    0, int((now - started_at).total_seconds())
                )
            except (TypeError, ValueError):
                item["duration_seconds"] = 0
        result.append(item)
    return result


def get_incident_summary():
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT
                COUNT(*) AS total_incidents,
                SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END)
                    AS active_incidents,
                SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END)
                    AS resolved_incidents,
                SUM(CASE WHEN status = 'Resolved'
                         THEN duration_seconds ELSE 0 END)
                    AS resolved_downtime_seconds
            FROM incidents
        """).fetchone()
    finally:
        connection.close()

    return {
        "total_incidents": row["total_incidents"] or 0,
        "active_incidents": row["active_incidents"] or 0,
        "resolved_incidents": row["resolved_incidents"] or 0,
        "resolved_downtime_seconds":
            row["resolved_downtime_seconds"] or 0
    }


def clear_incidents():
    connection = get_connection()
    try:
        connection.execute("DELETE FROM incidents")
        connection.commit()
    finally:
        connection.close()


def get_analytics(period="24h"):

    """

    Return monitoring analytics for all devices.



    Supported periods:

    24h = last 24 hours

    7d  = last 7 days

    30d = last 30 days

    """



    periods = {

        "24h": "-24 hours",

        "7d": "-7 days",

        "30d": "-30 days"

    }



    selected_period = periods.get(

        period,

        "-24 hours"

    )



    connection = get_connection()



    try:

        rows = connection.execute("""

            SELECT

                device_ip,



                COUNT(*) AS total_checks,



                SUM(

                    CASE

                        WHEN status = 'Online'

                        THEN 1

                        ELSE 0

                    END

                ) AS online_checks,



                SUM(

                    CASE

                        WHEN status = 'Offline'

                        THEN 1

                        ELSE 0

                    END

                ) AS offline_checks,



                AVG(

                    CASE

                        WHEN latency IS NOT NULL

                        THEN latency

                    END

                ) AS average_latency,



                MIN(

                    CASE

                        WHEN latency IS NOT NULL

                        THEN latency

                    END

                ) AS minimum_latency,



                MAX(

                    CASE

                        WHEN latency IS NOT NULL

                        THEN latency

                    END

                ) AS maximum_latency,



                AVG(packet_loss)

                    AS average_packet_loss



            FROM monitoring_history



            WHERE datetime(checked_at)

                >= datetime('now', 'localtime', ?)



            GROUP BY device_ip



            ORDER BY device_ip

        """, (selected_period,)).fetchall()



    finally:

        connection.close()



    analytics = []



    for row in rows:



        total_checks = row["total_checks"] or 0

        online_checks = row["online_checks"] or 0

        offline_checks = row["offline_checks"] or 0



        if total_checks > 0:

            availability = round(

                (online_checks / total_checks) * 100,

                2

            )

        else:

            availability = 0



        analytics.append({

            "ip": row["device_ip"],



            "availability": availability,



            "total_checks": total_checks,



            "online_checks": online_checks,



            "offline_checks": offline_checks,



            "average_latency": round(

                row["average_latency"] or 0,

                1

            ),



            "minimum_latency": round(

                row["minimum_latency"] or 0,

                1

            ),



            "maximum_latency": round(

                row["maximum_latency"] or 0,

                1

            ),



            "average_packet_loss": round(

                row["average_packet_loss"] or 0,

                1

            )

        })



    return analytics





def get_incident_count(device_ip, period="24h"):

    """

    Count offline incidents for a device

    during the selected period.

    """



    periods = {

        "24h": "-24 hours",

        "7d": "-7 days",

        "30d": "-30 days"

    }



    selected_period = periods.get(

        period,

        "-24 hours"

    )



    connection = get_connection()



    try:

        rows = connection.execute("""

            SELECT

                status,

                checked_at



            FROM monitoring_history



            WHERE device_ip = ?



            AND datetime(checked_at)

                >= datetime('now', 'localtime', ?)



            ORDER BY checked_at ASC

        """, (

            device_ip,

            selected_period

        )).fetchall()



    finally:

        connection.close()



    incidents = 0

    previous_status = None



    for row in rows:



        current_status = row["status"]



        if (

            current_status == "Offline"

            and previous_status != "Offline"

        ):

            incidents += 1



        previous_status = current_status



    return incidents





def get_analytics_summary(period="24h"):

    """

    Return complete analytics including

    per-device statistics and overall summary.

    """



    analytics = get_analytics(period)



    for device in analytics:

        device["incidents"] = get_incident_count(

            device["ip"],

            period

        )



    if not analytics:

        return {

            "period": period,

            "devices": [],

            "summary": {

                "devices": 0,

                "average_availability": 0,

                "average_latency": 0,

                "average_packet_loss": 0,

                "total_checks": 0,

                "total_incidents": 0

            }

        }



    device_count = len(analytics)



    average_availability = round(

        sum(

            device["availability"]

            for device in analytics

        ) / device_count,

        2

    )



    average_latency = round(

        sum(

            device["average_latency"]

            for device in analytics

        ) / device_count,

        1

    )



    average_packet_loss = round(

        sum(

            device["average_packet_loss"]

            for device in analytics

        ) / device_count,

        1

    )



    total_checks = sum(

        device["total_checks"]

        for device in analytics

    )



    total_incidents = sum(

        device["incidents"]

        for device in analytics

    )



    return {

        "period": period,



        "devices": analytics,



        "summary": {

            "devices": device_count,



            "average_availability":

                average_availability,



            "average_latency":

                average_latency,



            "average_packet_loss":

                average_packet_loss,



            "total_checks":

                total_checks,



            "total_incidents":

                total_incidents

        }

    }

if __name__ == "__main__":

    init_database()



    print(

        "Network monitoring database created successfully."

    )