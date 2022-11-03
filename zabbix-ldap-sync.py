#!/usr/bin/env python3

from re import M
import sys
import json
import ldap
import ldap.asyncsearch
import logging
import string
import random
import requests

if __name__ == "__main__":

    # Configuration loading
    print("Initializing zabbix-ldap-sync.")
    config = None
    with open("zabbix-ldap-sync.json") as f:
        config = json.load(f)
    if config is not None:
        print("Done.")

        # Logging
        print("Updating logger configuration")
        log_option = {"format": "[%(asctime)s] [%(levelname)s] %(message)s"}
        if config["log"]:
            log_option["filename"] = config["log"]
        if config["log_level"]:
            log_option["level"] = getattr(logging, str(config["log_level"]).upper())

        logging.basicConfig(**log_option)
        print("Done.")

        # Zabbix auth
        logging.info("Connecting to ZABBIX")
        logging.info("Connecting to ZABBIX")
        if (
            not config["zabbix"]["api"]
            and not config["zabbix"]["username"]
            and not config["zabbix"]["password"]
        ):
            logging.error("You should configure ZABBIX in config.json")
            sys.exit(1)
        r = requests.post(
            config["zabbix"]["api"] + "/api_jsonrpc.php",
            json={
                "jsonrpc": "2.0",
                "method": "user.login",
                "params": {
                    "user": config["zabbix"]["username"],
                    "password": config["zabbix"]["password"],
                },
                "id": 1,
            },
        )

        zab_token = r.json()["result"]

        r = requests.post(
            config["zabbix"]["api"] + "/api_jsonrpc.php",
            json={
                "jsonrpc": "2.0",
                "method": "authentication.update",
                "params": {
                    "ldap_configured": 1,
                    "ldap_host": config["ldap"]["url"],
                    "ldap_port": "389",
                    "ldap_base_dn": config["ldap"]["users_base_dn"],
                    "ldap_search_attribute": "uid",
                    "ldap_bind_dn": config["ldap"]["bind_dn"],
                    "ldap_bind_password": config["ldap"]["password"],
                },
                "auth": zab_token,
                "id": 1,
            },
        )

        admins_grpid = 0
        users_grpid = 0

        zabbix_admins = []
        zabbix_users = []

        logging.info("Retrieving ZABBIX groups")
        r = requests.post(
            config["zabbix"]["api"] + "/api_jsonrpc.php",
            json={
                "jsonrpc": "2.0",
                "method": "usergroup.get",
                "params": {"output": "extend", "status": 0},
                "auth": zab_token,
                "id": 1,
            },
        )

        for g in r.json()["result"]:
            if g["name"] == "Admins":
                admins_grpid = g["usrgrpid"]
            if g["name"] == "Users":
                users_grpid = g["usrgrpid"]

        logging.info("Retrieving ZABBIX users")
        r = requests.post(
            config["zabbix"]["api"] + "/api_jsonrpc.php",
            json={
                "jsonrpc": "2.0",
                "method": "user.get",
                "params": {"output": "extend", "selectUsrgrps": "True"},
                "auth": zab_token,
                "id": 1,
            },
        )

        for u in r.json()["result"]:
            if "usrgrps" in u.keys():
                if str(admins_grpid) in [usrgrp["usrgrpid"] for usrgrp in u["usrgrps"]]:
                    zabbix_admins.append(
                        {"uid": u["userid"], "username": u["username"]}
                    )
                if str(users_grpid) in [usrgrp["usrgrpid"] for usrgrp in u["usrgrps"]]:
                    zabbix_users.append({"uid": u["userid"], "username": u["username"]})

        # LDAP authentication
        logging.info("Connecting to LDAP")
        if not config["ldap"]["url"]:
            logging.error("You should configure LDAP in config.json")
            sys.exit(1)
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            l = ldap.initialize(uri=config["ldap"]["url"])
            l.simple_bind_s(config["ldap"]["bind_dn"], config["ldap"]["password"])
        except:
            logging.error("Error while connecting")
            sys.exit(1)

        logging.info("Done.")

        ldap_admins_gid = 0
        ldap_users_gid = 0

        ldap_admins = []
        ldap_users = []

        filterstr = "(&(objectClass=posixGroup)(|"
        filterstr += "(cn=%s)" % config["ldap"]["admins_group"]
        for g in config["ldap"]["users_groups"]:
            filterstr += "(cn=%s)" % g
        filterstr += "))"

        attrlist = ["cn", "memberUid", "gidNumber"]

        # Fetch users by group membership
        for group_dn, group_data in l.search_s(
            base=config["ldap"]["groups_base_dn"],
            scope=ldap.SCOPE_SUBTREE,
            filterstr=filterstr,
            attrlist=attrlist,
        ):

            if group_data["cn"][0].decode() == config["ldap"]["admins_group"]:
                ldap_admins_gid = group_data["gidNumber"][0].decode()
            elif group_data["cn"][0].decode() in config["ldap"]["users_groups"]:
                ldap_users_gid = group_data["gidNumber"][0].decode()

            if "memberUid" in group_data:
                for member in group_data["memberUid"]:
                    member = member.decode()
                    for user_dn, user_data in l.search_s(
                        base=config["ldap"]["users_base_dn"],
                        scope=ldap.SCOPE_SUBTREE,
                        filterstr="(&(uid=%s)(objectClass=posixAccount))" % member,
                        attrlist=["uid", "givenName", "sn"],
                    ):
                        user = {
                            "username": user_data["uid"][0].decode(),
                            "name": user_data["givenName"][0].decode(),
                            "surname": user_data["sn"][0].decode(),
                        }

                        if (
                            group_data["cn"][0].decode()
                            == config["ldap"]["admins_group"]
                        ):
                            ldap_admins.append(user)
                        elif (
                            group_data["cn"][0].decode()
                            in config["ldap"]["users_groups"]
                        ):
                            ldap_users.append(user)

        # Fetch users by primary group
        for user_dn, user_data in l.search_s(
            base=config["ldap"]["users_base_dn"],
            scope=ldap.SCOPE_SUBTREE,
            filterstr="(objectClass=posixAccount)",
            attrlist=["uid", "givenName", "sn", "gidNumber"],
        ):

            user = {
                "username": user_data["uid"][0].decode(),
                "name": user_data["givenName"][0].decode(),
                "surname": user_data["sn"][0].decode(),
            }

            if user_data["gidNumber"][0].decode() == ldap_admins_gid:
                ldap_admins.append(user)
            elif user_data["gidNumber"][0].decode() == ldap_users_gid:
                ldap_users.append(user)

        for l in ldap_admins:
            logging.info("Working on admin user %s ..." % l["username"])
            if l["username"] not in [z["username"] for z in zabbix_admins]:
                r = requests.post(
                    config["zabbix"]["api"] + "/api_jsonrpc.php",
                    json={
                        "jsonrpc": "2.0",
                        "method": "user.create",
                        "params": {
                            "username": l["username"],
                            "name": l["name"],
                            "surname": l["surname"],
                            "passwd": "".join(
                                random.choices(string.ascii_lowercase, k=20)
                            ),
                            "usrgrps": [{"usrgrpid": admins_grpid}],
                            "roleid": "2",
                        },
                        "auth": zab_token,
                        "id": 1,
                    },
                )
            else:
                logging.info("|- Admin user exists in ZABBIX, updating.")
                r = requests.post(
                    config["zabbix"]["api"] + "/api_jsonrpc.php",
                    json={
                        "jsonrpc": "2.0",
                        "method": "user.update",
                        "params": {
                            "userid": [
                                z["uid"]
                                for z in zabbix_admins
                                if z["username"] == l["username"]
                            ][0],
                            "username": l["username"],
                            "name": l["name"],
                            "surname": l["surname"],
                            "passwd": "".join(
                                random.choices(string.ascii_lowercase, k=20)
                            ),
                            "usrgrps": [{"usrgrpid": admins_grpid}],
                            "roleid": "2",
                        },
                        "auth": zab_token,
                        "id": 1,
                    },
                )

        for l in ldap_users:
            if l["username"] not in [l["username"] for l in ldap_admins]:
                logging.info("Working on regular user %s ..." % l["username"])
                if l["username"] not in [z["username"] for z in zabbix_users]:
                    logging.info("|- User does not exist in ZABBIX, creating.")
                    r = requests.post(
                        config["zabbix"]["api"] + "/api_jsonrpc.php",
                        json={
                            "jsonrpc": "2.0",
                            "method": "user.create",
                            "params": {
                                "username": l["username"],
                                "name": l["name"],
                                "surname": l["surname"],
                                "passwd": "".join(
                                    random.choices(string.ascii_lowercase, k=20)
                                ),
                                "usrgrps": [{"usrgrpid": users_grpid}],
                                "roleid": "1",
                            },
                            "auth": zab_token,
                            "id": 1,
                        },
                    )
                else:
                    logging.info("|- Regular user exists in ZABBIX, updating.")
                    r = requests.post(
                        config["zabbix"]["api"] + "/api_jsonrpc.php",
                        json={
                            "jsonrpc": "2.0",
                            "method": "user.update",
                            "params": {
                                "userid": [
                                    z["uid"]
                                    for z in zabbix_users
                                    if z["username"] == l["username"]
                                ][0],
                                "username": l["username"],
                                "name": l["name"],
                                "surname": l["surname"],
                                "passwd": "".join(
                                    random.choices(string.ascii_lowercase, k=20)
                                ),
                                "usrgrps": [{"usrgrpid": users_grpid}],
                                "roleid": "1",
                            },
                            "auth": zab_token,
                            "id": 1,
                        },
                    )

        zabbix_all = zabbix_admins + zabbix_users
        ldap_all = ldap_admins + ldap_users

        for z in zabbix_all:
            logging.info("Working on ZABBIX user %s ..." % z["username"])

            is_admin = z["username"] in [l["username"] for l in ldap_admins]
            is_user = z["username"] in [l["username"] for l in ldap_users]

            if is_admin or is_user:
                r = requests.post(
                    config["zabbix"]["api"] + "/api_jsonrpc.php",
                    json={
                        "jsonrpc": "2.0",
                        "method": "user.update",
                        "params": {
                            "userid": z["uid"],
                            "usrgrps": [
                                {"usrgrpid": admins_grpid if is_admin else users_grpid}
                            ],
                            "roleid": "1",
                        },
                        "auth": zab_token,
                        "id": 1,
                    },
                )
            else:
                logging.info("|- Deleting user %s ..." % z["username"])
                r = requests.post(
                    config["zabbix"]["api"] + "/api_jsonrpc.php",
                    json={
                        "jsonrpc": "2.0",
                        "method": "user.delete",
                        "params": [z["uid"]],
                        "auth": zab_token,
                        "id": 1,
                    },
                )

        # Logout user
        logging.info("Done")
        r = requests.post(
            config["zabbix"]["api"] + "/api_jsonrpc.php",
            json={
                "jsonrpc": "2.0",
                "method": "user.logout",
                "params": {},
                "id": 2,
                "auth": zab_token,
            },
        )
