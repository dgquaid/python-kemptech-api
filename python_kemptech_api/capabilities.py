DEFAULT = '7.1.34'

# Every loadmaster should have at least these capabilities
BASE_CAPABILITIES = [
    "reboot",
    "stats",
    "shutdown",
    "backup",
    "restore",
    "logs",
]

LOADMASTER_CAPABILITIES = BASE_CAPABILITIES
LOADMASTER_CAPABILITIES.extend([
    "templates",
    "firmware",
    "virtual_services",
])

CAPABILITIES = {
    DEFAULT: BASE_CAPABILITIES,
    "7.1.34": LOADMASTER_CAPABILITIES,
    "7.1.35": LOADMASTER_CAPABILITIES,
    "7.2.36": LOADMASTER_CAPABILITIES,
    "7.2.37": LOADMASTER_CAPABILITIES,
}
