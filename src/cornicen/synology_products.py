"""Product names and aliases shared by the RSS mapper and public diagnostics."""

SYNOLOGY_PRODUCTS = {
    name: ('Synology', product)
    for product, names in (
        ('DiskStation Manager (DSM)', ('DSM', 'DiskStation Manager', 'Synology DiskStation Manager (DSM)')),
        ('Synology Router Manager (SRM)', ('SRM', 'Router Manager', 'Synology Router Manager (SRM)')),
        ('Surveillance Station', ('Surveillance Station',)),
        ('Synology Photo Station', ('Photo Station', 'Synology Photo Station')),
        ('Calendar', ('Calendar', 'Synology Calendar')),
        ('Media Server', ('Media Server', 'Synology Media Server')),
        ('Active Backup for Business', ('Active Backup for Business',)),
        ('Download Station', ('Download Station', 'Synology Download Station')),
        ('BeeStation OS (BSM)', ('BeeStation OS', 'BSM')),
        ('Audio Station', ('Audio Station', 'Synology Audio Station')),
        ('Synology Assistant', ('Synology Assistant',)),
        ('MailPlus Server', ('MailPlus Server',)),
        ('Hyper Backup', ('Hyper Backup',)),
        ('Synology Drive Server', ('Synology Drive Server', 'Drive Server')),
        ('CardDAV Server', ('CardDAV Server', 'Synology CardDAV Server')),
        ('File Station', ('File Station', 'Synology File Station')),
        ('Mail Station', ('Mail Station',)),
        ('Synology Antivirus Essential', ('Antivirus Essential', 'Synology Antivirus Essential')),
        ('Synology Docker', ('Docker', 'Container Manager', 'Synology Docker')),
        ('DNS Server', ('DNS Server', 'Synology DNS Server')),
        ('VPN Plus Server', ('VPN Plus Server', 'Synology VPN Plus Server')),
        ('Camera Firmware', ('Camera Firmware', 'Camera BC500 Firmware')),
    )
    for name in names
}
