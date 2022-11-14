# zabbix-ldap-sync

Python project to sync LDAP Groups into Zabbix.

This script can be used to sync OpenLDAP users and groups with ZABBIX instance. However it can me modified to be compliant with Active Directory or some other LDAP provider as well. You can schedule this script using cron to keep your ZABBIX users and groups in sync continuously. This project is based on [georg3k/gitlab-ldap-sync](https://github.com/georg3k/gitlab-ldap-sync) project which is a fork of [MrBE4R/gitlab-ldap-sync](https://github.com/MrBE4R/gitlab-ldap-sync).

Features:
- ZABBIX API authentication
- LDAP -> ZABBIX groups mapping
    - Can be restricted to sync only certain groups
- LDAP -> ZABBIX users mapping
    - Can be restricted to sync only existent users
    - Respects both primary group and group entities in LDAP
- Automatically assigns admin users Zabbix admin role
- Logging for scheduled usage


> **Note**
> LDAP auth still needs to be enabled in your ZABBIX instance settings.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

This project has been tested on CentOS 7, CentOS 8 Stream, ZABBIX 5.4.* and OpenLDAP.

```
Python
pip3
python-ldap
```

### Installing

You could either install requirements system wide or use virtual environment / conda, choose your poison.

To get this up and running you just need to do the following :

* Clone the repo
```bash
git clone https://github.com/georg3k/zabbix-ldap-sync
```
* Install requirements
```bash
pip3 install -r ./zabbix-ldap-sync/requirements.txt
```
* Edit zabbix-ldap-sync.json with you settings
```bash
EDITOR ./zabbix-ldap-sync/zabbix-ldap-sync.json
```
* Start the script
```bash
cd ./zabbix-ldap-sync && ./zabbix-ldap-sync.py
```

You could add the script in a cron to run it periodically.
## Deployment

How to configure config.json
```json5
{
  "log": "/var/log/zabbix-ldap-sync.log",           // log file to write
  "log_level": "INFO",                              // log verbosity
  "zabbix": {
    "api": "https://zabbix.example.com",            // ZABBIX instance URL
    "username": "Admin",                            // ZABBIX admin username
    "password": "zabbix_password"                   // ZABBIX admin password
  },
  "ldap": {
    "url": "ldaps://ldap.example.com",              // LDAP server URL
    "users_base_dn": "ou=People,dc=example,dc=com", // LDAP tree users location
    "groups_base_dn": "ou=group,dc=example,dc=com", // LDAP tree groups location
    "bind_dn": "cn=readonly,dc=example,dc=com",     // LDAP bind username
    "password": "ldap_password",                    // LDAP bind password
    "admins_group": "admins",                       // LDAP group that should be synced with admins group in ZABBIX
    "users_groups": [ "developers", "testers" ]     // LDAP groups that should be granted regular user role in ZABBIX
  }
}

## Built With

* [Python](https://www.python.org/)
* [python-ldap](https://www.python-ldap.org/en/latest/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

