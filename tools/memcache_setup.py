#!/usr/bin/env python3
"""
Utility script for creating and managing Google Cloud Memcache instances.
"""
import argparse
import subprocess
import sys
import time


def run_command(cmd, check=True):
    """Run a shell command and return the output."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=check)
    return result.stdout.strip()


def enable_memcache_service(project):
    """Enable the Memcache API for the project."""
    print(f"Enabling Memcache API for project {project}...")
    run_command(["gcloud", "services", "enable", "memcache.googleapis.com",
                 f"--project={project}"])
    print("Memcache API enabled.")


def create_memcache_instance(project, name, region, node_count=1, node_cpu=1,
                             node_memory=1, network="default"):
    """Create a new Memcache instance."""
    print(f"Creating Memcache instance {name} in {region}...")

    cmd = [
        "gcloud", "memcache", "instances", "create", name,
        f"--project={project}",
        f"--region={region}",
        f"--node-count={node_count}",
        f"--node-cpu={node_cpu}",
        f"--node-memory={node_memory}GB",
        f"--network={network}"
    ]

    run_command(cmd)
    print(f"Memcache instance {name} created.")

    # Wait a bit for the instance to be ready
    print("Waiting for instance to be ready...")
    time.sleep(5)

    # Get instance info
    describe_instance(project, name, region)


def describe_instance(project, name, region):
    """Get information about a Memcache instance."""
    print(f"Getting information about Memcache instance {name}...")
    cmd = [
        "gcloud", "memcache", "instances", "describe", name,
        f"--project={project}",
        f"--region={region}",
        "--format=json"
    ]

    output = run_command(cmd)
    print(f"Instance details:\n{output}")

    # Also get the discovery endpoint (connection info)
    cmd = [
        "gcloud", "memcache", "instances", "describe", name,
        f"--project={project}",
        f"--region={region}",
        "--format=value(discoveryEndpoint)"
    ]

    endpoint = run_command(cmd)
    print(f"\nConnection string: {endpoint}")

    # Parse the endpoint as host:port
    if ":" in endpoint:
        host, port = endpoint.split(":")
        print(f"Memcache Host: {host}")
        print(f"Memcache Port: {port}")
    else:
        print(f"Memcache Host: {endpoint}")
        print("Memcache Port: 11211 (default)")

    print("\nUse these values in your ReversibleAnonymizer configuration.")


def create_firewall_rule(project, network="default"):
    """Create firewall rule to allow access to Memcache from Vertex AI notebooks."""
    print(f"Creating firewall rule for Memcache access in project {project}...")

    # Check if rule already exists
    cmd = [
        "gcloud", "compute", "firewall-rules", "list",
        f"--project={project}",
        "--filter=name:allow-memcache",
        "--format=value(name)"
    ]

    output = run_command(cmd, check=False)
    if "allow-memcache" in output:
        print("Firewall rule 'allow-memcache' already exists.")
        return

    cmd = [
        "gcloud", "compute", "firewall-rules", "create", "allow-memcache",
        f"--project={project}",
        f"--network={network}",
        "--allow=tcp:11211",
        "--source-ranges=10.0.0.0/8",
        "--description=Allow Vertex AI notebooks to access Memcached"
    ]

    run_command(cmd)
    print("Firewall rule created.")


def main():
    parser = argparse.ArgumentParser(
        description="Utility for Google Cloud Memcache setup for ReversibleAnonymizer"
    )

    parser.add_argument("--project", "-p", required=True,
                        help="Google Cloud project ID")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Enable API command
    enable_parser = subparsers.add_parser("enable-api",
                                          help="Enable Memcache API for your project")

    # Create instance command
    create_parser = subparsers.add_parser("create",
                                          help="Create a new Memcache instance")
    create_parser.add_argument("--name", required=True,
                               help="Name for the Memcache instance")
    create_parser.add_argument("--region", default="us-central1",
                               help="Google Cloud region for the instance")
    create_parser.add_argument("--node-count", type=int, default=1,
                               help="Number of Memcache nodes")
    create_parser.add_argument("--node-cpu", type=int, default=1,
                               help="CPU cores per node")
    create_parser.add_argument("--node-memory", type=int, default=1,
                               help="Memory per node in GB")
    create_parser.add_argument("--network", default="default",
                               help="VPC network to use")

    # Describe instance command
    describe_parser = subparsers.add_parser("describe",
                                            help="Get information about a Memcache instance")
    describe_parser.add_argument("--name", required=True,
                                 help="Name of the Memcache instance")
    describe_parser.add_argument("--region", default="us-central1",
                                 help="Google Cloud region for the instance")

    # Create firewall rule command
    firewall_parser = subparsers.add_parser("create-firewall-rule",
                                            help="Create firewall rule for Vertex AI access")
    firewall_parser.add_argument("--network", default="default",
                                 help="VPC network to use")

    args = parser.parse_args()

    if args.command == "enable-api":
        enable_memcache_service(args.project)
    elif args.command == "create":
        create_memcache_instance(
            args.project, args.name, args.region,
            args.node_count, args.node_cpu, args.node_memory,
            args.network
        )
    elif args.command == "describe":
        describe_instance(args.project, args.name, args.region)
    elif args.command == "create-firewall-rule":
        create_firewall_rule(args.project, args.network)


if __name__ == "__main__":
    main()