# Bridge-local DNS forwarder. Tracks the host resolver so the agent follows
# host Wi-Fi DNS changes without container recreation. Standard library only.
FROM python:3.12-slim-bookworm

COPY forwarder.py /opt/dns/forwarder.py

# The service grants only NET_BIND_SERVICE (port 53); nothing here needs root.
USER 65534:65534

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["python3", "/opt/dns/forwarder.py"]
