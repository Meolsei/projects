"""Command-line interface for 0x0.st file hosting service.

This script provides a wrapper around curl for interacting with 0x0.st, a
temporary file hosting service. It handles file uploads, URL shortening, and
file management with straightforward command-line options.

Upload Operations:
    - File uploads with validation (existence, type, non-empty).
    - Raw text data uploads via stdin.
    - Remote URL copying.
    - Optional secret URL generation.
    - Custom expiration times in hours.
    - Management token extraction from HTTP headers.

Management Operation:
    * Requires both file URL and management token.
    - File deletion.
    - Expiration time modification.

Implementation:
    Uses subprocess to execute curl commands with multipart/form-data encoding.
    Parses HTTP response headers to extract X-Token values and URLs.
    Validates mutually exclusive upload modes and provides clear error messages.
    Sets custom User-Agent for service operator identification.

Constants:
    API_URL (str): The 0x0.st API endpoint.
    USER_AGENT (str): Custom User-Agent identification.

Example:
    Upload a file with a secret URL and 24-hour expiration, and get the token:
        $ python 0x0.py -f document.pdf -s -e 24 -t

    Delete a previously uploaded file:
        $ python 0x0.py --manage-url URL --manage-token TOKEN --delete

"""

import argparse
import os
import sys
import subprocess

API_URL = "https://0x0.st"
USER_AGENT = "0x0.py/1.0 (uploader written in Python)"

parser = argparse.ArgumentParser(description="Upload files, data, or URLs to 0x0.st, a temporary file hosting service. Supports expiration times, secret URLs, and management tokens.")

parser._action_groups[1].title = "Options"
next(a for a in parser._actions if a.dest == "help").help = "Show this help message and exit"

upload_group = parser.add_argument_group("Upload")
upload = upload_group.add_mutually_exclusive_group()
upload.add_argument("-f", "--file", metavar="path", help="Upload a file")
upload.add_argument("-d", "--data", metavar="data", help="Upload raw text")
upload.add_argument("-u", "--url", metavar="url", help="Upload from URL")

management = parser.add_argument_group("Manage")
management.add_argument("--manage-token", metavar="token", help="Specify management token")
management.add_argument("--manage-url", metavar="url", help="Manage specified URL")
management.add_argument("--delete", action="store_true", help="Delete the file")
management.add_argument("--change-expire", type=int, metavar="hrs", help="Change expiry time in hours")

upload_opts = parser.add_argument_group("Flags")
upload_opts.add_argument("-s", "--secret", action="store_true", help="Generate longer URL")
upload_opts.add_argument("-e", "--expire", type=int, metavar="hrs", help="Set expiry time in hours")
upload_opts.add_argument("-t", "--token", action="store_true", help="Show X-Token header for management")

args = parser.parse_args()

UPLOAD_ARGS = ["file", "data", "url"]
MANAGEMENT_ARGS = ["manage_url", "manage_token", "delete", "change_expire"]

is_upload = any(getattr(args, arg) for arg in UPLOAD_ARGS)
is_management = any(getattr(args, arg) for arg in MANAGEMENT_ARGS)

if not (is_management or is_upload):
    parser.print_help()
    sys.exit(1)

if is_upload and is_management:
    print("Error: Cannot upload and manage at the same time")
    sys.exit(1)


def validate(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"'{filepath}' is not a valid path.")
    if not os.path.isfile(filepath):
        raise ValueError(f"'{filepath}' is not a file.")
    if os.path.getsize(filepath) == 0:
        raise ValueError(f"'{filepath}' is an empty file.")


def parse_upload(output):
    """Extract URL and X-Token from curl response"""
    lines = output.split("\n")
    token = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("X-Token:")), None)
    url = next((l.strip() for l in lines if l.startswith("https://")), None)
    return url, token


def add_optional_flags(cmd):
    """Add optional flags to curl command"""
    cmd.extend(["-A", USER_AGENT])

    if args.token:
        cmd.insert(1, "-i")
    if args.secret:
        cmd.extend(["-F", "secret="])
    if args.expire:
        if args.expire < 1:
            raise ValueError("Expiration must be at least 1 hour.")
        cmd.extend(["-F", f"expires={args.expire}"])

    return cmd


def execute_upload(cmd, stdin_data=None):
    """Execute upload command and handle response"""
    cmd = add_optional_flags(cmd)

    if stdin_data:
        result = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        output = result.stdout.strip()

        if args.token:
            url, token = parse_upload(output)
            print(f"URL: {url}\nToken: {token}" if url and token else output)
        else:
            print(output)
    else:
        raise Exception(f"Upload failed: {result.stderr}")


try:
    if args.file:
        validate(args.file)
        execute_upload(["curl", "-F", f"file=@{args.file}", API_URL])

    elif args.data:
        execute_upload(["curl", "-F", "file=@-", API_URL], stdin_data=args.data)

    elif args.url:
        execute_upload(["curl", "-F", f"url={args.url}", API_URL])

    elif is_management:
        if not (args.manage_url and args.manage_token):
            raise ValueError("Management requires both --manage-url and --manage-token")

        if not (args.delete or args.change_expire):
            raise ValueError("Must specify --delete or --change-expire")

        cmd = ["curl", "-A", USER_AGENT, "-F", f"token={args.manage_token}"]

        if args.delete:
            cmd.extend(["-F", "delete="])

        if args.change_expire:
            if args.change_expire < 1:
                raise ValueError("Expiration must be at least 1 hour.")
            cmd.extend(["-F", f"expires={args.change_expire}"])

        cmd.append(args.manage_url)

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            if args.delete:
                print(f"Successfully deleted: {args.manage_url}")
            elif args.change_expire:
                print(f"Updated expiration to {args.change_expire} hour(s): {args.manage_url}")
            if result.stdout.strip():
                print(f"Server response: {result.stdout.strip()}")
        else:
            raise Exception(f"Management operation failed: {result.stderr}")

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
