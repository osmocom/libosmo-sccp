#!/usr/bin/env python3

app_configs = {
    "osmo-stp": ["doc/examples/osmo-stp.cfg"],
}

apps = [(4239, "stp/osmo-stp", "OsmoSTP", "osmo-stp"),
        ]

vty_command = ["./stp/osmo-stp", "-c", "doc/examples/osmo-stp.cfg"]

vty_app = apps[0]
