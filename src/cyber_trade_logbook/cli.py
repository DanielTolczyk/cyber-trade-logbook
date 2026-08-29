"""CLI Interface for The Cybersecurity Trade Project Logbook."""

import sys
import os
import argparse
import http.server
import socketserver
from pathlib import Path
from .crypto import TradeKeyManager


def serve_command(port: int = 8000):
    """Serve the local-first PWA dashboard."""
    public_dir = Path(__file__).parent.parent.parent / "public"
    if not public_dir.exists():
        print(f"Error: Static directory not found at {public_dir}")
        sys.exit(1)

    os.chdir(public_dir)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Serving Cyber Trade Logbook at http://localhost:{port}")
        print("Press Ctrl+C to terminate.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


def keygen_command(out_path: str = "trade_key.pem"):
    """Generate a new Ed25519 Trade Signing Key."""
    priv, pub = TradeKeyManager.generate_keypair()
    priv_pem = TradeKeyManager.serialize_private_key(priv)
    pub_pem = TradeKeyManager.serialize_public_key(pub)

    with open(out_path, "wb") as f:
        f.write(priv_pem)
    pub_path = out_path.replace(".pem", ".pub.pem")
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    print(f"Generated Ed25519 Private Key: {out_path}")
    print(f"Generated Ed25519 Public Key:  {pub_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Trade Logbook - Local-First Digital Ledger & CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # serve
    serve_parser = subparsers.add_parser("serve", help="Launch local PWA dashboard")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")

    # keygen
    key_parser = subparsers.add_parser("keygen", help="Generate Ed25519 Trade Keypair")
    key_parser.add_argument("--out", type=str, default="trade_key.pem", help="Output file path")

    args = parser.parse_args()
    if args.command == "serve":
        serve_command(port=args.port)
    elif args.command == "keygen":
        keygen_command(out_path=args.out)


if __name__ == "__main__":
    main()
