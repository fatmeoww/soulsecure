#!/usr/bin/env python3
"""config-service -- generic internal service for Module 3 Lab 2's SSRF
demo (not cloud-metadata specific). No published port, no vhost/DNS.
Reachable only by other containers on the Compose network via Docker's
built-in service-name DNS (i.e. only via api's SSRF routes, same as
imds-sim).
"""
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def root():
    return jsonify(
        service="soulsecure-internal-config",
        env="prod",
        db_host="orders-db.internal.soulsecure.lab",
        flag="flag{8124333151ec60d870737fc1a5b60b4c}",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8500)
