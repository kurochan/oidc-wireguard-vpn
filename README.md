oidc-wireguard-vpn
=====
manipulate WireGuard with OpenID Connect Client Initiated Backchannel Authentication(CIBA) Flow

# Requirements
* Linux
* WireGuard
* nftables

# Build
```bash
make build
```

# Configure
```bash
cp oidc-wireguard-vpn.example.yaml oidc-wireguard-vpn.yaml
vim oidc-wireguard-vpn.yaml
```

# Run
```bash
export WG_PRIVATE_KEY="wireguard private key"
export OIDC_CLIENT_ID="oidc client id"
export OIDC_CLIENT_SECRET="oidc client secret"
sudo ./oidc-wireguard-vpn
```
