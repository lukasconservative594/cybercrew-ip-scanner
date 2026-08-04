"""Built-in OUI prefixes (first three MAC octets) to vendor names.

This is a curated subset covering the hardware you actually meet on an
internal network, with deliberate emphasis on hypervisors and SBCs - knowing
a host is a VMware guest or a Raspberry Pi changes how you treat it. Run
"Tools -> Update MAC vendor database" to pull the full IEEE registry, which
takes precedence over this table once downloaded.
"""

from __future__ import annotations

OUI: dict[str, str] = {
    # --- virtualisation / cloud (high value for triage) -------------------
    "000569": "VMware", "000C29": "VMware", "001C14": "VMware",
    "005056": "VMware", "0050F2": "Microsoft",
    "080027": "VirtualBox", "0A0027": "VirtualBox",
    "00155D": "Microsoft Hyper-V", "00125A": "Microsoft",
    "525400": "QEMU/KVM", "5254AB": "QEMU/KVM",
    "00163E": "Xen", "001C42": "Parallels", "0021F6": "Oracle VM",
    "024232": "Docker", "0242AC": "Docker",
    "0EF7C4": "Amazon EC2", "029000": "Amazon", "F01FAF": "Dell",
    "16FF1E": "Google Cloud", "42010A": "Google Cloud",

    # --- single board computers / IoT -------------------------------------
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading", "28CDC1": "Raspberry Pi Trading",
    "D83ADD": "Raspberry Pi Trading", "2CCF67": "Raspberry Pi Trading",
    "240AC4": "Espressif", "30AEA4": "Espressif", "3C71BF": "Espressif",
    "5CCF7F": "Espressif", "840D8E": "Espressif", "A020A6": "Espressif",
    "ACD074": "Espressif", "B4E62D": "Espressif", "CC50E3": "Espressif",
    "ECFABC": "Espressif", "7C9EBD": "Espressif", "84F3EB": "Espressif",
    "083AF2": "Espressif", "349454": "Espressif", "40F520": "Espressif",
    "00049F": "Freescale", "001199": "Arduino",

    # --- network vendors ---------------------------------------------------
    "00000C": "Cisco", "000142": "Cisco", "0001C7": "Cisco",
    "000A41": "Cisco", "001121": "Cisco", "0018BA": "Cisco",
    "001B0C": "Cisco", "002155": "Cisco", "00259C": "Cisco",
    "0050F0": "Cisco", "6C503E": "Cisco", "F02572": "Cisco",
    "E8B748": "Cisco", "00D0BC": "Cisco", "506B8D": "Cisco Meraki",
    "88157A": "Cisco Meraki", "E0CB1D": "Cisco Meraki",
    "0004DD": "Cisco", "001A2F": "Cisco",

    "000B86": "Aruba Networks", "6CF37F": "Aruba Networks",
    "18645C": "Aruba Networks", "9C1C12": "Aruba Networks",
    "204C03": "Aruba Networks", "D8C7C8": "Aruba Networks",

    "0017DF": "Juniper", "2C6BF5": "Juniper", "3C61041": "Juniper",
    "5C5EAB": "Juniper", "78FE3D": "Juniper", "F4B52F": "Juniper",

    "0009F5": "Huawei", "00E0FC": "Huawei", "1C1D67": "Huawei",
    "283152": "Huawei", "48DB50": "Huawei", "5CA86A": "Huawei",
    "781DBA": "Huawei", "C4072F": "Huawei", "E0247F": "Huawei",
    "FC48EF": "Huawei", "00259E": "Huawei",

    "0015FF": "MikroTik", "4C5E0C": "MikroTik", "6C3B6B": "MikroTik",
    "744D28": "MikroTik", "B869F4": "MikroTik", "CC2DE0": "MikroTik",
    "DC2C6E": "MikroTik", "E48D8C": "MikroTik", "2CC81B": "MikroTik",

    "0418D6": "Ubiquiti", "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti",
    "68725V": "Ubiquiti", "788A20": "Ubiquiti", "802AA8": "Ubiquiti",
    "B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti", "F09FC2": "Ubiquiti",
    "FCECDA": "Ubiquiti", "74ACB9": "Ubiquiti", "E063DA": "Ubiquiti",

    "000FB5": "NETGEAR", "001B2F": "NETGEAR", "008EF2": "NETGEAR",
    "20E52A": "NETGEAR", "2C3033": "NETGEAR", "44944C": "NETGEAR",
    "A040A0": "NETGEAR", "C03F0E": "NETGEAR", "E091F5": "NETGEAR",

    "001E58": "D-Link", "00265A": "D-Link", "1CBDB9": "D-Link",
    "34081F": "D-Link", "78542E": "D-Link", "9094E4": "D-Link",
    "C8BE19": "D-Link", "F07D68": "D-Link",

    "000AEB": "TP-Link", "14CC20": "TP-Link", "1C61B4": "TP-Link",
    "3C84 6A": "TP-Link", "50C7BF": "TP-Link", "5C63BF": "TP-Link",
    "6466B3": "TP-Link", "A42BB0": "TP-Link", "C46E1F": "TP-Link",
    "E894F6": "TP-Link", "F4F26D": "TP-Link", "AC84C6": "TP-Link",

    "001349": "ZyXEL", "00A0C5": "ZyXEL", "5CE28C": "ZyXEL",
    "B0B2DC": "ZyXEL", "SC1234": "ZyXEL",

    "0090CC": "Planet", "000BFC": "Cisco", "001018": "Broadcom",
    "0010DB": "Juniper", "00907F": "WatchGuard", "000E8F": "Sercomm",
    "00095B": "NETGEAR", "0024A5": "Buffalo", "10C37B": "ASUSTek",
    "1C872C": "ASUSTek", "2C56DC": "ASUSTek", "381428": "ASUSTek",
    "50465D": "ASUSTek", "704D7B": "ASUSTek", "AC220B": "ASUSTek",
    "BCEE7B": "ASUSTek", "D850E6": "ASUSTek", "F832E4": "ASUSTek",

    "000C42": "Routerboard", "0003C6": "Fortinet", "00090F": "Fortinet",
    "085B0E": "Fortinet", "704CA5": "Fortinet", "9017AC": "Fortinet",
    "E82689": "Fortinet", "0009B7": "Cisco", "001C7F": "Check Point",
    "00E02B": "Extreme Networks", "0204 06": "Palo Alto Networks",
    "001B17": "Palo Alto Networks", "B4 0C25": "Palo Alto Networks",
    "0050 43": "Marvell", "001CF0": "D-Link", "0026F2": "NETGEAR",

    # --- servers, workstations, laptops -----------------------------------
    "001560": "Hewlett Packard", "0017A4": "Hewlett Packard",
    "001B78": "Hewlett Packard", "0021 5A": "Hewlett Packard",
    "002264": "Hewlett Packard", "0025B3": "Hewlett Packard",
    "1458D0": "Hewlett Packard", "2C4138": "Hewlett Packard",
    "3822D6": "Hewlett Packard", "3C4A92": "Hewlett Packard",
    "40A8F0": "Hewlett Packard", "6CC217": "Hewlett Packard",
    "9457A5": "Hewlett Packard", "A0481C": "Hewlett Packard",
    "B499BA": "Hewlett Packard", "F430B9": "Hewlett Packard",
    "98E7F4": "Hewlett Packard", "00306E": "Hewlett Packard",

    "000BDB": "Dell", "00123F": "Dell", "0014 22": "Dell",
    "001EC9": "Dell", "002219": "Dell", "0024E8": "Dell",
    "14FEB5": "Dell", "18A99B": "Dell", "246E96": "Dell",
    "34177F": "Dell", "509A4C": "Dell", "5CF9DD": "Dell",
    "742B62": "Dell", "84 7BEB": "Dell", "B083FE": "Dell",
    "B885 84": "Dell", "D067E5": "Dell", "F8BC12": "Dell",
    "F8DB88": "Dell", "1866DA": "Dell", "A4BB6D": "Dell",

    "000629": "IBM", "00096B": "IBM", "001A64": "IBM",
    "00215E": "IBM", "5CF3FC": "IBM", "E41F13": "IBM",
    "6CAE8B": "IBM", "08 002B": "DEC",

    "0002B3": "Intel", "000E0C": "Intel", "001320": "Intel",
    "001B21": "Intel", "001E67": "Intel", "0021 6A": "Intel",
    "0024D7": "Intel", "3417EB": "Intel", "34E12D": "Intel",
    "3C9702": "Intel", "44032C": "Intel", "5CE0C5": "Intel",
    "7085C2": "Intel", "8C554A": "Intel", "94659C": "Intel",
    "A0A8CD": "Intel", "B4D5BD": "Intel", "E4B318": "Intel",
    "F8341A": "Intel", "9C2976": "Intel", "48513B": "Intel",

    "00089B": "Lenovo", "00121C": "Lenovo", "1C6F65": "Lenovo",
    "3C18A0": "Lenovo", "54EE75": "Lenovo", "6C0B84": "Lenovo",
    "8CDCD4": "Lenovo", "A4C3F0": "Lenovo", "E85AD1": "Lenovo",

    "0003FF": "Microsoft", "0017FA": "Microsoft", "281878": "Microsoft",
    "3C8375": "Microsoft", "485073": "Microsoft", "58 82A8": "Microsoft",
    "7CED8D": "Microsoft", "C4 9DED": "Microsoft", "F01DBC": "Microsoft",

    "000393": "Apple", "000A27": "Apple", "001451": "Apple",
    "001EC2": "Apple", "0023DF": "Apple", "0026B0": "Apple",
    "109ADD": "Apple", "14109F": "Apple", "24AB81": "Apple",
    "28CFE9": "Apple", "3451C9": "Apple", "40331A": "Apple",
    "4C8D79": "Apple", "5855CA": "Apple", "60FACD": "Apple",
    "68967B": "Apple", "7CD1C3": "Apple", "8C8590": "Apple",
    "98F0AB": "Apple", "A45E60": "Apple", "B8E856": "Apple",
    "C82A14": "Apple", "D0E140": "Apple", "E0ACCB": "Apple",
    "F0DBE2": "Apple", "F82793": "Apple", "AC BC32": "Apple",

    # --- phones / consumer -------------------------------------------------
    "0016DB": "Samsung", "0021 19": "Samsung", "0023 39": "Samsung",
    "08D42B": "Samsung", "18227E": "Samsung", "241B7A": "Samsung",
    "34AA8B": "Samsung", "5001BB": "Samsung", "5CF6DC": "Samsung",
    "78 1FDB": "Samsung", "8C71F8": "Samsung", "A02195": "Samsung",
    "C81479": "Samsung", "E8508B": "Samsung", "FCC734": "Samsung",

    "0022A1": "Huawei", "286C07": "Xiaomi", "3480B3": "Xiaomi",
    "506583": "Xiaomi", "64B473": "Xiaomi", "7C1DD9": "Xiaomi",
    "8CBEBE": "Xiaomi", "9C99A0": "Xiaomi", "F8A45F": "Xiaomi",

    "001E75": "LG Electronics", "0022A9": "LG Electronics",
    "10683F": "LG Electronics", "344DF7": "LG Electronics",
    "A039F7": "LG Electronics", "C4366C": "LG Electronics",

    "001A80": "Sony", "0013A9": "Sony", "30F9ED": "Sony",
    "5453ED": "Sony", "B4527D": "Sony", "FC0FE6": "Sony",

    "3C5AB4": "Google", "44070B": "Google", "6466B3": "Google",
    "94EB2C": "Google", "F4F5D8": "Google", "F4F5E8": "Google",
    "003EE1": "Apple", "0C4DE9": "Apple",

    "0C47C9": "Amazon", "34D270": "Amazon", "44650D": "Amazon",
    "68 37E9": "Amazon", "747548": "Amazon", "A002DC": "Amazon",
    "FC65DE": "Amazon", "F0272D": "Amazon",

    "000E58": "Sonos", "347E5C": "Sonos", "5CAAFD": "Sonos",
    "B8E937": "Sonos", "0017 88": "Philips Hue", "001788": "Philips Hue",
    "ECB5FA": "Philips Hue",

    # --- storage / NAS -----------------------------------------------------
    "0011 32": "Synology", "001132": "Synology", "0011D8": "ASUSTek",
    "000C43": "Ralink", "24 0A64": "QNAP", "00089F": "QNAP",
    "001C 2A": "QNAP", "00 D0 43": "Western Digital", "0090A9": "Western Digital",
    "00 1D7D": "Giga-Byte", "0014EE": "Western Digital",
    "0004 CF": "Seagate", "0011 D8": "Seagate",

    # --- printers ----------------------------------------------------------
    "00000E": "Fujitsu", "000048": "Seiko Epson", "0026AB": "Seiko Epson",
    "44D884": "Seiko Epson", "000085": "Canon", "001E8F": "Canon",
    "2C9EFC": "Canon", "00807 3": "Brother", "008077": "Brother",
    "0080 92": "Brother", "30055C": "Brother", "001B A9": "Brother",
    "00000F": "Xerox", "0000AA": "Xerox", "9C934E": "Xerox",
    "0000 74": "Ricoh", "002673": "Ricoh", "00 26 73": "Ricoh",
    "0017C8": "Kyocera", "001BA9": "Brother",

    # --- cameras / physical security / OT ---------------------------------
    "00408C": "Axis Communications", "ACCC8E": "Axis Communications",
    "B8A44F": "Axis Communications", "00 40 8C": "Axis Communications",
    "44 19B6": "Hikvision", "4419B6": "Hikvision", "BCAD28": "Hikvision",
    "C0 56E3": "Hikvision", "18680B": "Hikvision", "586ED6": "Hikvision",
    "3C EF8C": "Dahua", "3CEF8C": "Dahua", "9C14 63": "Dahua",
    "E0 5061": "Dahua", "4C11BF": "Dahua",
    "0010 83": "Honeywell", "001083": "Honeywell",
    "00 0FBB": "Siemens", "000FBB": "Siemens", "001C06": "Siemens",
    "0800 06": "Siemens", "0080F4": "Telemecanique",
    "0000BC": "Rockwell Automation", "0001D7": "F5 Networks",
    "0090E8": "Moxa", "00 90E8": "Moxa", "0C 8C24": "Moxa",

    # --- misc chipsets often seen behind consumer gear ---------------------
    "000E2E": "Edimax", "001C10": "Cisco-Linksys", "0021 29": "Cisco-Linksys",
    "0016B6": "Cisco-Linksys", "68 7F74": "Cisco-Linksys",
    "525400": "QEMU/KVM", "000424": "Realtek", "52 5400": "QEMU/KVM",
    "000EC6": "Realtek", "00E04C": "Realtek", "001C25": "Hon Hai",
    "0021 CC": "Hon Hai", "3C 970E": "Wistron", "8C89A5": "Micro-Star",
    "00 1A92": "ASUSTek", "D43D7E": "Micro-Star", "4CCC6A": "Micro-Star",
    "001FC6": "ASUSTek", "0019DB": "Micro-Star", "70 85C2": "ASRock",
}


def normalise(prefix: str) -> str:
    return "".join(ch for ch in prefix.upper() if ch in "0123456789ABCDEF")[:6]


#: cleaned copy - the literal above tolerates stray spaces for readability
OUI_CLEAN: dict[str, str] = {}
for _prefix, _vendor in OUI.items():
    _key = normalise(_prefix)
    if len(_key) == 6:
        OUI_CLEAN.setdefault(_key, _vendor)
