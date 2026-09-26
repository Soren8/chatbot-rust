# Bridge-local DNS

The Compose `dns` sidecar polls the Linux host's resolver files through read-only `/etc` and `/run` directory mounts every two seconds. Webserver, voice-service, and tests use its pinned bridge address (`172.29.0.53`); override `DNS_SUBNET` and `DNS_ADDRESS` together if that subnet conflicts. Recreate the Compose default network when changing the subnet.

It selects up to three non-loopback nameservers, including systemd-resolved and NetworkManager uplinks when the primary resolver is a loopback stub. Queries fail over in order via UDP or TCP; no public DNS fallback or per-domain split-DNS routing is provided. When no host upstream is usable, queries receive no answer. Only `/etc` and `/run` resolver paths are supported; other symlink targets are unreadable. The broad read-only mounts include host files and sockets, so the sidecar runs unprivileged with only `NET_BIND_SERVICE` and a read-only root filesystem.

Run `python3 -m unittest discover -s dns/tests -t dns -v` from the repository root. Before `docker compose run --rm tests`, start the sidecar with `docker compose up -d --build dns`; one-off `run` does not reliably start its DNS dependency. The host test executor runs its own test containers and does not use this Compose service.
