from flask import Flask, render_template, jsonify, request, session, redirect, url_for







import subprocess







import platform







import socket







import psutil







import re







import ipaddress







import json







import os

import asyncio







from concurrent.futures import ThreadPoolExecutor, as_completed







from datetime import datetime







from database import (



    init_database,



    save_monitoring_result,



    calculate_uptime,



    get_device_statistics,



    get_recent_history,



    save_event,



    get_events,



    get_analytics_summary,



        open_incident,

    resolve_incident,

    get_incidents,

    get_incident_summary,

clear_events as clear_database_events



)







app = Flask(__name__)

app.secret_key = os.environ.get("NETSCOPE_SECRET_KEY", "change-this-netscope-secret")

AUTH_ENABLED = os.environ.get("NETSCOPE_AUTH_ENABLED", "1") != "0"

NETSCOPE_USERNAME = os.environ.get("NETSCOPE_USERNAME", "admin")

NETSCOPE_PASSWORD = os.environ.get("NETSCOPE_PASSWORD", "NetScope123!")







init_database()







DEVICES_FILE = "devices.json"







EVENTS_FILE = "events.json"







DEFAULT_DEVICES = [







    {"name": "Google DNS", "ip": "8.8.8.8", "removable": False},







    {"name": "Cloudflare DNS", "ip": "1.1.1.1", "removable": False},







]







previous_status = {}







cpu_alert_active = False







ram_alert_active = False







# Network performance alert states



latency_alerts = {}



packet_loss_alerts = {}







# Default network alert thresholds



alert_thresholds = {



    "latency": 150,



    "packet_loss": 10



}







# Prevent saving duplicate history when the homepage







# and API are requested almost at the same time.







last_history_save = {}







# -------------------------







# FILE MANAGEMENT







# -------------------------







def save_json(filename, data):







    try:







        with open(filename, "w", encoding="utf-8") as file:







            json.dump(







                data,







                file,







                indent=4,







                ensure_ascii=False







            )







    except Exception as error:







        print(f"Error saving {filename}: {error}")







def load_devices():







    if not os.path.exists(DEVICES_FILE):







        save_json(DEVICES_FILE, DEFAULT_DEVICES)







        return [device.copy() for device in DEFAULT_DEVICES]







    try:







        with open(DEVICES_FILE, "r", encoding="utf-8") as file:







            data = json.load(file)







        if isinstance(data, list):







            return data







    except Exception:







        pass







    save_json(DEVICES_FILE, DEFAULT_DEVICES)







    return [device.copy() for device in DEFAULT_DEVICES]







def load_events():







    if not os.path.exists(EVENTS_FILE):







        save_json(EVENTS_FILE, [])







        return []







    try:







        with open(EVENTS_FILE, "r", encoding="utf-8") as file:







            data = json.load(file)







        if isinstance(data, list):







            return data







    except Exception:







        pass







    return []







devices = load_devices()







events = []  # SQLite is the event source







# -------------------------







# EVENT LOG







# -------------------------







def add_event(event_type, title, message, severity="info"):



    save_event(



        event_type,



        title,



        message,



        severity



    )











def ping_device(ip, timeout=2, count=4):



    """



    Ping a device multiple times.







    Returns:



        status



        average_latency



        packet_loss



    """



    try:



        system = platform.system().lower()







        if system == "windows":



            command = [



                "ping",



                "-n",



                str(count),



                "-w",



                str(timeout * 1000),



                ip



            ]



        else:



            command = [



                "ping",



                "-c",



                str(count),



                "-W",



                str(timeout),



                ip



            ]







        result = subprocess.run(



            command,



            capture_output=True,



            text=True,



            timeout=(timeout * count) + 3



        )







        output = (result.stdout or "") + "\n" + (result.stderr or "")







        # Extract reply latency values. This avoids depending on the



        # localized Windows "loss" summary text.



        latency_values = re.findall(



            r"time[=<]\s*(\d+)\s*ms",



            output,



            re.IGNORECASE



        )







        latencies = [int(value) for value in latency_values]







        less_than_one = len(



            re.findall(



                r"time\s*<\s*1\s*ms",



                output,



                re.IGNORECASE



            )



        )



        latencies.extend([1] * less_than_one)







        replies = min(len(latencies), count)







        # If Windows reports success but its localized output did not match



        # the latency expression, still treat the target as reachable.



        if replies == 0 and result.returncode == 0:



            status = "Online"



            packet_loss = 0.0



            average_latency = None



        elif replies > 0:



            status = "Online"



            packet_loss = round(((count - replies) / count) * 100, 1)



            average_latency = round(sum(latencies) / len(latencies), 1)



        else:



            status = "Offline"



            packet_loss = 100.0



            average_latency = None







        return status, average_latency, packet_loss







    except Exception:



        return "Offline", None, 100.0











def get_local_ip():







    try:







        connection = socket.socket(







            socket.AF_INET,







            socket.SOCK_DGRAM







        )







        connection.connect(







            ("8.8.8.8", 80)







        )







        ip = connection.getsockname()[0]







        connection.close()







        return ip







    except Exception:







        return "127.0.0.1"







def get_uptime():







    boot_time = datetime.fromtimestamp(







        psutil.boot_time()







    )







    uptime = datetime.now() - boot_time







    days = uptime.days







    hours, remainder = divmod(







        uptime.seconds,







        3600







    )







    minutes, _ = divmod(







        remainder,







        60







    )







    if days > 0:







        return f"{days}d {hours}h {minutes}m"







    if hours > 0:







        return f"{hours}h {minutes}m"







    return f"{minutes}m"







def get_system_health(cpu, ram):







    if cpu >= 90 or ram >= 90:







        return "Critical"







    if cpu >= 75 or ram >= 75:







        return "Warning"







    return "Healthy"







def get_hostname(ip):







    try:







        return socket.gethostbyaddr(ip)[0]







    except Exception:







        return "Unknown Device"







# -------------------------







# HISTORY







# -------------------------







def should_save_history(ip, seconds=15):







    now = datetime.now()







    previous = last_history_save.get(ip)







    if previous is None:







        last_history_save[ip] = now







        return True







    difference = (







        now - previous







    ).total_seconds()







    if difference >= seconds:







        last_history_save[ip] = now







        return True







    return False







# -------------------------







# ALERT SYSTEM







# -------------------------







def check_device_status_change(







    name,







    ip,







    current_status







):







    global previous_status







    if ip not in previous_status:







        previous_status[ip] = current_status







        return







    old_status = previous_status[ip]







    if old_status == current_status:







        return







    if current_status == "Offline":









        open_incident(ip, name, "Critical")



        add_event(







            "device_offline",







            "Device Offline",







            f"{name} ({ip}) is no longer responding.",







            "critical"







        )







    elif current_status == "Online":









        resolve_incident(ip)



        add_event(







            "device_online",







            "Device Back Online",







            f"{name} ({ip}) is responding again.",







            "success"







        )







    previous_status[ip] = current_status







def check_system_alerts(cpu, ram):







    global cpu_alert_active







    global ram_alert_active







    if cpu >= 90 and not cpu_alert_active:







        add_event(







            "high_cpu",







            "High CPU Usage",







            f"Local system CPU usage reached {cpu}%.",







            "critical"







        )







        cpu_alert_active = True







    elif cpu < 75 and cpu_alert_active:







        add_event(







            "cpu_recovered",







            "CPU Usage Recovered",







            f"Local system CPU usage returned to {cpu}%.",







            "success"







        )







        cpu_alert_active = False







    if ram >= 90 and not ram_alert_active:







        add_event(







            "high_ram",







            "High RAM Usage",







            f"Local system RAM usage reached {ram}%.",







            "critical"







        )







        ram_alert_active = True







    elif ram < 75 and ram_alert_active:







        add_event(







            "ram_recovered",







            "RAM Usage Recovered",







            f"Local system RAM usage returned to {ram}%.",







            "success"







        )







        ram_alert_active = False







# -------------------------







# NETWORK DISCOVERY







# -------------------------







def check_network_performance_alerts(name, ip, status, latency, packet_loss):



    global latency_alerts



    global packet_loss_alerts







    if status != "Online":



        latency_alerts.pop(ip, None)



        packet_loss_alerts.pop(ip, None)



        return







    latency_threshold = alert_thresholds["latency"]



    packet_loss_threshold = alert_thresholds["packet_loss"]







    if latency is not None:



        if latency >= latency_threshold and not latency_alerts.get(ip, False):



            add_event(



                "high_latency",



                "High Network Latency",



                f"{name} ({ip}) latency reached {latency} ms. "



                f"Threshold: {latency_threshold} ms.",



                "warning"



            )



            latency_alerts[ip] = True



        elif latency < latency_threshold and latency_alerts.get(ip, False):



            add_event(



                "latency_recovered",



                "Network Latency Recovered",



                f"{name} ({ip}) latency returned to {latency} ms.",



                "success"



            )



            latency_alerts[ip] = False







    if packet_loss is not None:



        if (



            packet_loss >= packet_loss_threshold



            and packet_loss < 100



            and not packet_loss_alerts.get(ip, False)



        ):



            add_event(



                "packet_loss",



                "Packet Loss Detected",



                f"{name} ({ip}) packet loss reached {packet_loss}%. "



                f"Threshold: {packet_loss_threshold}%.",



                "warning"



            )



            packet_loss_alerts[ip] = True



        elif (



            packet_loss < packet_loss_threshold



            and packet_loss_alerts.get(ip, False)



        ):



            add_event(



                "packet_loss_recovered",



                "Packet Loss Recovered",



                f"{name} ({ip}) packet loss returned to {packet_loss}%.",



                "success"



            )



            packet_loss_alerts[ip] = False







def scan_single_device(ip):







    status, latency, packet_loss = ping_device(







        ip,







        timeout=1,







        count=1







    )







    if status == "Online":







        return {







            "name": get_hostname(ip),







            "ip": ip,







            "status": status,







            "latency": latency,







            "packet_loss": packet_loss







        }







    return None







def scan_network():







    local_ip = get_local_ip()







    if local_ip == "127.0.0.1":







        return []







    try:







        network = ipaddress.ip_network(







            local_ip + "/24",







            strict=False







        )







    except ValueError:







        return []







    addresses = [







        str(ip)







        for ip in network.hosts()







    ]







    discovered_devices = []







    with ThreadPoolExecutor(







        max_workers=40







    ) as executor:







        futures = {







            executor.submit(







                scan_single_device,







                ip







            ): ip







            for ip in addresses







        }







        for future in as_completed(







            futures







        ):







            try:







                device = future.result()







                if device:







                    discovered_devices.append(







                        device







                    )







            except Exception:







                pass







    discovered_devices.sort(







        key=lambda device:







        tuple(







            int(part)







            for part







            in device["ip"].split(".")







        )







    )







    return discovered_devices







# -------------------------







# MONITORING







# -------------------------







def collect_devices():







    monitored_devices = []







    hostname = socket.gethostname()







    local_ip = get_local_ip()







    cpu = round(







        psutil.cpu_percent(







            interval=0.2







        ),







        1







    )







    ram = round(







        psutil.virtual_memory().percent,







        1







    )







    check_system_alerts(







        cpu,







        ram







    )







    # Local machine







    if should_save_history(local_ip):







        save_monitoring_result(







            local_ip,







            "Online",







            0,







            0







        )







    local_uptime_percentage = (







        calculate_uptime(local_ip)







    )







    local_stats = (







        get_device_statistics(local_ip)







    )







    monitored_devices.append({







        "name": hostname,







        "ip": local_ip,







        "status": "Online",







        "latency": 0,







        "packet_loss": 0,







        "cpu": cpu,







        "ram": ram,







        "uptime": get_uptime(),







        "uptime_percentage":







            local_uptime_percentage,







        "average_latency":







            local_stats["average_latency"],







        "minimum_latency":







            local_stats["minimum_latency"],







        "maximum_latency":







            local_stats["maximum_latency"],







        "health":







            get_system_health(cpu, ram),







        "last_check":







            datetime.now().strftime("%H:%M:%S"),







        "removable": False







    })







    # Remote devices







    for device in devices:







        status, latency, packet_loss = (







            ping_device(







                device["ip"],







                timeout=1,







                count=4







            )







        )







        check_device_status_change(







            device["name"],







            device["ip"],







            status







        )







        check_network_performance_alerts(



            device["name"],



            device["ip"],



            status,



            latency,



            packet_loss



        )







        if should_save_history(







            device["ip"]







        ):







            save_monitoring_result(







                device["ip"],







                status,







                latency,







                packet_loss







            )







        uptime_percentage = (







            calculate_uptime(







                device["ip"]







            )







        )







        stats = get_device_statistics(







            device["ip"]







        )







        monitored_devices.append({







            "name": device["name"],







            "ip": device["ip"],







            "status": status,







            "latency": latency,







            "packet_loss": packet_loss,







            "cpu": None,







            "ram": None,







            "uptime": "--",







            "uptime_percentage":







                uptime_percentage,







            "average_latency":







                stats["average_latency"],







            "minimum_latency":







                stats["minimum_latency"],







            "maximum_latency":







                stats["maximum_latency"],







            "health": (







                "Online"







                if status == "Online"







                else "Offline"







            ),







            "last_check":







                datetime.now().strftime(







                    "%H:%M:%S"







                ),







            "removable":







                device.get(







                    "removable",







                    True







                )







        })







    return monitored_devices







# -------------------------







# ROUTES







# -------------------------







@app.before_request

def require_login():

    if not AUTH_ENABLED:

        return None

    if request.endpoint in {"login", "static"}:

        return None

    if session.get("netscope_authenticated"):

        return None

    if request.path.startswith("/api/"):

        return jsonify({"success": False, "message": "Authentication required."}), 401

    return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])

def login():

    error = None

    if request.method == "POST":

        if request.form.get("username") == NETSCOPE_USERNAME and request.form.get("password") == NETSCOPE_PASSWORD:

            session["netscope_authenticated"] = True

            session.permanent = True

            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template("login.html", error=error)



@app.route("/logout", methods=["GET", "POST"])

def logout():

    session.clear()

    return redirect(url_for("login"))



@app.route("/")







def home():







    monitored_devices = collect_devices()







    total = len(







        monitored_devices







    )







    online = sum(







        1







        for device in monitored_devices







        if device["status"] == "Online"







    )







    offline = total - online







    return render_template(







        "index.html",







        devices=monitored_devices,







        total=total,







        online=online,







        offline=offline







    )







@app.route("/api/status")







def api_status():







    monitored_devices = collect_devices()







    total = len(







        monitored_devices







    )







    online = sum(







        1







        for device in monitored_devices







        if device["status"] == "Online"







    )







    offline = total - online







    return jsonify({







        "devices": monitored_devices,







        "total": total,







        "online": online,







        "offline": offline,







        "system_health": (







            round(







                (online / total) * 100







            )







            if total







            else 0







        ),







        "timestamp":







            datetime.now().strftime(







                "%H:%M:%S"







            )







    })







@app.route("/api/device/<ip>/statistics")







def device_statistics(ip):







    try:







        ipaddress.ip_address(ip)







    except ValueError:







        return jsonify({







            "success": False,







            "message":







                "Invalid IP address."







        }), 400







    statistics = (







        get_device_statistics(ip)







    )







    statistics["uptime_percentage"] = (







        calculate_uptime(ip)







    )







    statistics["ip"] = ip







    return jsonify(statistics)







@app.route("/api/device/<ip>/history")







def device_history(ip):







    try:







        ipaddress.ip_address(ip)







    except ValueError:







        return jsonify({







            "success": False,







            "message":







                "Invalid IP address."







        }), 400







    history = get_recent_history(







        ip,







        limit=50







    )







    return jsonify({







        "ip": ip,







        "history": history,







        "count": len(history)







    })







@app.route("/api/events")



def api_events():



    current_events = get_events(limit=100)



    return jsonify({



        "events": current_events,



        "count": len(current_events)



    })











@app.route("/api/events/clear", methods=["POST"])



def clear_events():



    clear_database_events()



    return jsonify({



        "success": True,



        "message": "Event log cleared."



    })









@app.route("/api/incidents")

def api_incidents():

    status = request.args.get("status")



    if status not in {None, "", "Active", "Resolved"}:

        return jsonify({

            "success": False,

            "message": "Invalid incident status."

        }), 400



    current_incidents = get_incidents(

        limit=100,

        status=status or None

    )



    return jsonify({

        "incidents": current_incidents,

        "count": len(current_incidents),

        "summary": get_incident_summary()

    })





@app.route("/api/incidents/summary")

def api_incident_summary():

    return jsonify(get_incident_summary())





@app.route("/api/analytics")



def api_analytics():



    period = request.args.get(



        "period",



        "24h"



    )







    allowed_periods = {



        "24h",



        "7d",



        "30d"



    }







    if period not in allowed_periods:



        return jsonify({



            "success": False,



            "message": "Invalid analytics period."



        }), 400







    analytics = get_analytics_summary(



        period



    )







    return jsonify(analytics)





# -------------------------

# SNMP MONITORING

# -------------------------



SNMP_DEFAULT_COMMUNITY = os.environ.get("NETSCOPE_SNMP_COMMUNITY", "public")



def _format_snmp_uptime(value):

    """Convert SNMP TimeTicks (hundredths of a second) to a readable duration."""

    try:

        total_seconds = int(value) // 100

    except (TypeError, ValueError):

        return str(value)



    days, remainder = divmod(total_seconds, 86400)

    hours, remainder = divmod(remainder, 3600)

    minutes, seconds = divmod(remainder, 60)



    parts = []

    if days:

        parts.append(f"{days}d")

    if hours or days:

        parts.append(f"{hours}h")

    if minutes or hours or days:

        parts.append(f"{minutes}m")

    parts.append(f"{seconds}s")

    return " ".join(parts)





async def _snmp_get_async(ip, community, oid, timeout=1.5, retries=0):

    # PySNMP 7.x exposes the asyncio high-level API.

    from pysnmp.hlapi.v3arch.asyncio import (

        SnmpEngine,

        CommunityData,

        UdpTransportTarget,

        ContextData,

        ObjectType,

        ObjectIdentity,

        get_cmd,

    )



    transport = await UdpTransportTarget.create(

        (ip, 161),

        timeout=timeout,

        retries=retries,

    )



    error_indication, error_status, error_index, var_binds = await get_cmd(

        SnmpEngine(),

        CommunityData(community, mpModel=1),  # SNMP v2c

        transport,

        ContextData(),

        ObjectType(ObjectIdentity(oid)),

    )



    if error_indication:

        raise RuntimeError(str(error_indication))



    if error_status:

        position = int(error_index) if error_index else 0

        raise RuntimeError(

            f"{error_status.prettyPrint()} at index {position}"

        )



    if not var_binds:

        raise RuntimeError("No SNMP response received.")



    return var_binds[0][1].prettyPrint()





def snmp_get(ip, community, oid):

    return asyncio.run(_snmp_get_async(ip, community, oid))





def get_snmp_system_info(ip, community=SNMP_DEFAULT_COMMUNITY):

    oids = {

        "description": "1.3.6.1.2.1.1.1.0",  # sysDescr.0

        "uptime_ticks": "1.3.6.1.2.1.1.3.0", # sysUpTime.0

        "name": "1.3.6.1.2.1.1.5.0",         # sysName.0

    }



    values = {}

    for key, oid in oids.items():

        values[key] = snmp_get(ip, community, oid)



    return {

        "success": True,

        "ip": ip,

        "version": "SNMPv2c",

        "name": values["name"],

        "description": values["description"],

        "uptime": _format_snmp_uptime(values["uptime_ticks"]),

        "uptime_ticks": values["uptime_ticks"],

    }





@app.route("/api/snmp/<ip>")

def api_snmp(ip):

    try:

        parsed = ipaddress.ip_address(ip)

        if parsed.version != 4:

            raise ValueError

    except ValueError:

        return jsonify({

            "success": False,

            "message": "Invalid IPv4 address."

        }), 400



    community = str(

        request.args.get("community", SNMP_DEFAULT_COMMUNITY)

    ).strip()



    if not community:

        return jsonify({

            "success": False,

            "message": "SNMP community cannot be empty."

        }), 400



    try:

        return jsonify(get_snmp_system_info(ip, community))

    except Exception as error:

        return jsonify({

            "success": False,

            "ip": ip,

            "version": "SNMPv2c",

            "message": (

                "No SNMP response. Make sure SNMP is enabled on the device, "

                "UDP port 161 is reachable, and the community string is correct."

            ),

            "detail": str(error),

        }), 200






# -------------------------
# SNMP INTERFACE MONITORING
# -------------------------

def _snmp_int(value, field_name):
    """Convert an SNMP numeric value to int with a useful error."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise RuntimeError(f"Invalid SNMP value for {field_name}: {value}")


def _snmp_status_text(value):
    mapping = {
        1: "Up",
        2: "Down",
        3: "Testing",
        4: "Unknown",
        5: "Dormant",
        6: "Not Present",
        7: "Lower Layer Down",
    }
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return str(value)
    return mapping.get(number, f"Unknown ({number})")


def _format_mac_from_snmp(value):
    """Best-effort formatting for SNMP physical-address output."""
    raw = str(value or "").strip()
    if not raw:
        return "--"

    # PySNMP may return a hex string such as 0x001122334455.
    if raw.lower().startswith("0x"):
        hex_value = raw[2:]
        if len(hex_value) == 12:
            return ":".join(
                hex_value[index:index + 2].upper()
                for index in range(0, 12, 2)
            )

    return raw


def get_snmp_interfaces(ip, community=SNMP_DEFAULT_COMMUNITY):
    """Read standard IF-MIB interface information through SNMPv2c."""
    if_count_raw = snmp_get(
        ip,
        community,
        "1.3.6.1.2.1.2.1.0"  # ifNumber.0
    )
    if_count = _snmp_int(if_count_raw, "ifNumber")

    # Safety cap: do not let a bad/hostile SNMP value create thousands of requests.
    if if_count < 0 or if_count > 256:
        raise RuntimeError(f"Unexpected interface count: {if_count}")

    interfaces = []

    for index in range(1, if_count + 1):
        base = f"1.3.6.1.2.1.2.2.1"

        description = snmp_get(ip, community, f"{base}.2.{index}")   # ifDescr
        interface_type = snmp_get(ip, community, f"{base}.3.{index}")  # ifType
        mtu = snmp_get(ip, community, f"{base}.4.{index}")          # ifMtu
        speed = snmp_get(ip, community, f"{base}.5.{index}")        # ifSpeed
        mac = snmp_get(ip, community, f"{base}.6.{index}")          # ifPhysAddress
        admin_status = snmp_get(ip, community, f"{base}.7.{index}") # ifAdminStatus
        oper_status = snmp_get(ip, community, f"{base}.8.{index}")  # ifOperStatus
        in_octets = snmp_get(ip, community, f"{base}.10.{index}")   # ifInOctets
        out_octets = snmp_get(ip, community, f"{base}.16.{index}")  # ifOutOctets

        interfaces.append({
            "index": index,
            "name": description or f"Interface {index}",
            "type": _snmp_int(interface_type, "ifType"),
            "mtu": _snmp_int(mtu, "ifMtu"),
            "speed_bps": _snmp_int(speed, "ifSpeed"),
            "mac": _format_mac_from_snmp(mac),
            "admin_status": _snmp_status_text(admin_status),
            "oper_status": _snmp_status_text(oper_status),
            "in_octets": _snmp_int(in_octets, "ifInOctets"),
            "out_octets": _snmp_int(out_octets, "ifOutOctets"),
        })

    return {
        "success": True,
        "ip": ip,
        "version": "SNMPv2c",
        "interface_count": len(interfaces),
        "interfaces": interfaces,
    }


@app.route("/api/snmp/<ip>/interfaces")
def api_snmp_interfaces(ip):
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4:
            raise ValueError
    except ValueError:
        return jsonify({
            "success": False,
            "message": "Invalid IPv4 address."
        }), 400

    community = str(
        request.args.get("community", SNMP_DEFAULT_COMMUNITY)
    ).strip()

    if not community:
        return jsonify({
            "success": False,
            "message": "SNMP community cannot be empty."
        }), 400

    try:
        return jsonify(get_snmp_interfaces(ip, community))
    except Exception as error:
        return jsonify({
            "success": False,
            "ip": ip,
            "version": "SNMPv2c",
            "interface_count": 0,
            "interfaces": [],
            "message": (
                "SNMP interface data is not available. "
                "The device must expose the standard IF-MIB."
            ),
            "detail": str(error),
        }), 200


@app.route("/api/traffic")

def api_traffic():

    counters = psutil.net_io_counters()

    return jsonify({

        "bytes_sent": counters.bytes_sent,

        "bytes_recv": counters.bytes_recv,

        "packets_sent": counters.packets_sent,

        "packets_recv": counters.packets_recv,

        "errors_in": counters.errin,

        "errors_out": counters.errout,

        "drops_in": counters.dropin,

        "drops_out": counters.dropout,

        "timestamp": datetime.now().isoformat(timespec="seconds")

    })



@app.route("/api/scan")







def api_scan():







    discovered = scan_network()







    local_ip = get_local_ip()







    network_name = (







        local_ip.rsplit(







            ".",







            1







        )[0] + ".0/24"







        if local_ip != "127.0.0.1"







        else "Unavailable"







    )







    monitored_ips = {







        device["ip"]







        for device in devices







    }







    monitored_ips.add(local_ip)







    for device in discovered:







        device["monitored"] = (







            device["ip"]







            in monitored_ips







        )







    return jsonify({







        "devices": discovered,







        "count": len(discovered),







        "network": network_name,







        "timestamp":







            datetime.now().strftime(







                "%H:%M:%S"







            )







    })







@app.route(







    "/api/add-device",







    methods=["POST"]







)







def add_device():







    global devices







    data = (







        request.get_json(







            silent=True







        ) or {}







    )







    name = str(







        data.get(







            "name",







            ""







        )







    ).strip()







    ip = str(







        data.get(







            "ip",







            ""







        )







    ).strip()







    if not ip:







        return jsonify({







            "success": False,







            "message":







                "IP address is required."







        }), 400







    try:







        ipaddress.ip_address(ip)







    except ValueError:







        return jsonify({







            "success": False,







            "message":







                "Invalid IP address."







        }), 400







    if ip == get_local_ip():







        return jsonify({







            "success": False,







            "message":







                "This computer is already monitored."







        }), 409







    if any(







        device["ip"] == ip







        for device in devices







    ):







        return jsonify({







            "success": False,







            "message":







                "Device is already being monitored."







        }), 409







    if (







        not name or







        name == "Unknown Device"







    ):







        name = (







            f"Network Device ({ip})"







        )







    new_device = {







        "name": name,







        "ip": ip,







        "removable": True







    }







    devices.append(







        new_device







    )







    save_json(







        DEVICES_FILE,







        devices







    )







    add_event(







        "device_added",







        "Device Added",







        f"{name} ({ip}) was added to monitoring.",







        "info"







    )







    return jsonify({







        "success": True,







        "message":







            f"{name} added and saved."







    })







@app.route(







    "/api/remove-device",







    methods=["POST"]







)







def remove_device():







    global devices







    data = (







        request.get_json(







            silent=True







        ) or {}







    )







    ip = str(







        data.get(







            "ip",







            ""







        )







    ).strip()







    target = next(







        (







            device







            for device in devices







            if device["ip"] == ip







        ),







        None







    )







    if target is None:







        return jsonify({







            "success": False,







            "message":







                "Device not found."







        }), 404







    if not target.get(







        "removable",







        True







    ):







        return jsonify({







            "success": False,







            "message":







                "Default monitoring devices cannot be removed."







        }), 403







    devices = [







        device







        for device in devices







        if device["ip"] != ip







    ]







    save_json(







        DEVICES_FILE,







        devices







    )







    previous_status.pop(







        ip,







        None







    )







    last_history_save.pop(







        ip,







        None







    )







    add_event(







        "device_removed",







        "Device Removed",







        f"{target['name']} ({ip}) was removed from monitoring.",







        "warning"







    )







    return jsonify({







        "success": True,







        "message":







            f"{target['name']} removed from monitoring."







    })







if __name__ == "__main__":







    init_database()







    app.run(debug=True)
