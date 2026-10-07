import asyncio
import socket
import psutil

# ==========================================
# Python 3.14 compatibility
# ==========================================

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c


# ==========================================
# NetScope SNMP Live Agent
# ==========================================

snmp_engine = engine.SnmpEngine()
computer_name = socket.gethostname()


# ==========================================
# SNMP Transport
# ==========================================

config.add_transport(
    snmp_engine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().open_server_mode(("0.0.0.0", 161))
)


# ==========================================
# SNMP v2c Community
# ==========================================

config.add_v1_system(
    snmp_engine,
    "netscope-area",
    "public"
)

config.add_vacm_user(
    snmp_engine,
    2,
    "netscope-area",
    "noAuthNoPriv",
    (1, 3, 6)
)


# ==========================================
# SNMP Context / MIB Builder
# ==========================================

snmp_context = context.SnmpContext(snmp_engine)
mib_builder = snmp_context.get_mib_instrum().get_mib_builder()

MibScalar, MibScalarInstance = mib_builder.import_symbols(
    "SNMPv2-SMI",
    "MibScalar",
    "MibScalarInstance"
)


# ==========================================
# Set standard SNMP System Name
# ==========================================

try:
    sys_name_instance, = mib_builder.import_symbols(
        "__SNMPv2-MIB",
        "sysName"
    )
    sys_name_instance.syntax = sys_name_instance.syntax.clone(computer_name)
except Exception as error:
    print(f"Warning: could not set sysName: {error}")


# ==========================================
# Helpers
# ==========================================

def get_real_interfaces():
    """Return useful Windows network interfaces detected by psutil."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    names = []
    preferred_words = (
        "ethernet",
        "wi-fi",
        "wifi",
        "wireless",
        "wlan",
    )

    # Prefer normal physical Ethernet/Wi-Fi adapters.
    for name in stats:
        lower = name.lower()
        if any(word in lower for word in preferred_words):
            names.append(name)

    # Fallback: active non-loopback adapters.
    if not names:
        for name, info in stats.items():
            lower = name.lower()
            if (
                info.isup
                and "loopback" not in lower
                and name in addrs
            ):
                names.append(name)

    # Keep stable ordering and avoid duplicates.
    return list(dict.fromkeys(names))


def get_interface_mac(interface_name):
    for address in psutil.net_if_addrs().get(interface_name, []):
        family_text = str(address.family)
        if (
            getattr(psutil, "AF_LINK", None) == address.family
            or "AF_LINK" in family_text
            or "AF_PACKET" in family_text
        ):
            raw = (address.address or "").replace("-", "").replace(":", "")
            if len(raw) == 12:
                try:
                    return bytes.fromhex(raw)
                except ValueError:
                    pass

    return b""


def get_interface_type(interface_name):
    lower = interface_name.lower()

    if any(word in lower for word in ("wi-fi", "wifi", "wireless", "wlan")):
        return 71  # ieee80211

    return 6  # ethernetCsmacd


def get_interface_stats(interface_name):
    return psutil.net_if_stats().get(interface_name)


def get_interface_io(interface_name):
    return psutil.net_io_counters(pernic=True).get(interface_name)


def counter32(value):
    # IF-MIB ifInOctets/ifOutOctets are Counter32.
    return int(value or 0) % (2 ** 32)


interface_names = get_real_interfaces()

if not interface_names:
    raise RuntimeError(
        "No usable network interfaces were detected by psutil."
    )


# ==========================================
# Dynamic MIB instance
# ==========================================

class DynamicMibScalarInstance(MibScalarInstance):
    def __init__(self, name, index, syntax, value_getter):
        super().__init__(name, index, syntax)
        self.value_getter = value_getter

    def getValue(self, name, **context):
        value = self.value_getter()
        return self.getSyntax().clone(value)


# ==========================================
# NetScope custom test object
# ==========================================

mib_builder.export_symbols(
    "__NETSCOPE_TEST_MIB",

    MibScalar(
        (1, 3, 6, 1, 4, 1, 99999, 1),
        v2c.OctetString()
    ),

    DynamicMibScalarInstance(
        (1, 3, 6, 1, 4, 1, 99999, 1),
        (0,),
        v2c.OctetString("NetScope"),
        lambda: f"NetScope SNMP Live Agent - {socket.gethostname()}"
    )
)


# ==========================================
# IF-MIB - ifNumber.0
# ==========================================

mib_builder.export_symbols(
    "__NETSCOPE_IF_NUMBER",

    MibScalar(
        (1, 3, 6, 1, 2, 1, 2, 1),
        v2c.Integer32()
    ),

    DynamicMibScalarInstance(
        (1, 3, 6, 1, 2, 1, 2, 1),
        (0,),
        v2c.Integer32(len(interface_names)),
        lambda: len(interface_names)
    )
)


# ==========================================
# IF-MIB column definitions
# ==========================================

ifDescr = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 2),
    v2c.OctetString()
)

ifType = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 3),
    v2c.Integer32()
)

ifMtu = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 4),
    v2c.Integer32()
)

ifSpeed = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 5),
    v2c.Gauge32()
)

ifPhysAddress = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 6),
    v2c.OctetString()
)

ifAdminStatus = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 7),
    v2c.Integer32()
)

ifOperStatus = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 8),
    v2c.Integer32()
)

ifInOctets = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 10),
    v2c.Counter32()
)

ifOutOctets = MibScalar(
    (1, 3, 6, 1, 2, 1, 2, 2, 1, 16),
    v2c.Counter32()
)


mib_builder.export_symbols(
    "__NETSCOPE_IF_COLUMNS",
    ifDescr,
    ifType,
    ifMtu,
    ifSpeed,
    ifPhysAddress,
    ifAdminStatus,
    ifOperStatus,
    ifInOctets,
    ifOutOctets
)


# ==========================================
# Dynamic interface instances
# ==========================================

for index, interface_name in enumerate(interface_names, start=1):

    def current_stats(name=interface_name):
        return get_interface_stats(name)

    def current_io(name=interface_name):
        return get_interface_io(name)

    mib_builder.export_symbols(
        f"__NETSCOPE_INTERFACE_{index}",

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 2),
            (index,),
            v2c.OctetString(interface_name),
            lambda name=interface_name: name
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 3),
            (index,),
            v2c.Integer32(get_interface_type(interface_name)),
            lambda name=interface_name: get_interface_type(name)
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 4),
            (index,),
            v2c.Integer32(1500),
            lambda name=interface_name: (
                get_interface_stats(name).mtu
                if get_interface_stats(name)
                else 1500
            )
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 5),
            (index,),
            v2c.Gauge32(0),
            lambda name=interface_name: min(
                int(
                    (
                        get_interface_stats(name).speed
                        if get_interface_stats(name)
                        else 0
                    ) * 1_000_000
                ),
                4_294_967_295
            )
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 6),
            (index,),
            v2c.OctetString(get_interface_mac(interface_name)),
            lambda name=interface_name: get_interface_mac(name)
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 7),
            (index,),
            v2c.Integer32(1),
            lambda name=interface_name: (
                1 if (
                    get_interface_stats(name)
                    and get_interface_stats(name).isup
                ) else 2
            )
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 8),
            (index,),
            v2c.Integer32(1),
            lambda name=interface_name: (
                1 if (
                    get_interface_stats(name)
                    and get_interface_stats(name).isup
                ) else 2
            )
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 10),
            (index,),
            v2c.Counter32(0),
            lambda name=interface_name: counter32(
                get_interface_io(name).bytes_recv
                if get_interface_io(name)
                else 0
            )
        ),

        DynamicMibScalarInstance(
            (1, 3, 6, 1, 2, 1, 2, 2, 1, 16),
            (index,),
            v2c.Counter32(0),
            lambda name=interface_name: counter32(
                get_interface_io(name).bytes_sent
                if get_interface_io(name)
                else 0
            )
        )
    )


# ==========================================
# SNMP Responders
# ==========================================

cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)


# ==========================================
# Agent information
# ==========================================

print("")
print("==========================================")
print("       NetScope SNMP Live Agent")
print("==========================================")
print(f"Computer:    {computer_name}")
print("IP:          0.0.0.0 (All local interfaces)")
print("Port:        161")
print("Version:     SNMPv2c")
print("Community:   public")
print("Access:      Read Only")
print(f"Interfaces:  {len(interface_names)}")
print("------------------------------------------")

for index, name in enumerate(interface_names, start=1):
    stats = get_interface_stats(name)
    status = "UP" if stats and stats.isup else "DOWN"
    speed = stats.speed if stats else 0
    print(f"{index} - {name} | {status} | {speed} Mbps")

print("------------------------------------------")
print("Mode:        LIVE Windows data")
print("Status:      RUNNING")
print("==========================================")
print("")
print("Press CTRL+C to stop the SNMP Agent.")
print("")


# ==========================================
# Start SNMP Agent
# ==========================================

snmp_engine.transport_dispatcher.job_started(1)

try:
    snmp_engine.open_dispatcher()

except KeyboardInterrupt:
    print("")
    print("NetScope SNMP Agent stopped.")

finally:
    snmp_engine.close_dispatcher()
