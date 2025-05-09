#!/usr/bin/env python3

import argparse
import sys
import socket
import os
import locale
from typing import Dict, List, Tuple, Any

try:
    import vici
except ImportError:
    print("Error: vici module not found. Please install it with 'pip install vici'", file=sys.stderr)
    sys.exit(2)

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Check StrongSwan IPSec status via VICI interface")
    parser.add_argument("--host", default="127.0.0.1", help="VICI server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4502, help="VICI TCP port (default: 4502)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose output and exception tracing")
    parser.add_argument("--ascii", action="store_true", help="Force ASCII output instead of UTF-8 symbols")
    return parser.parse_args()

def connect_to_vici(host: str, port: int, debug: bool) -> Tuple[vici.Session, socket.socket]:
    """Establish a connection to the VICI interface."""
    try:
        # Create a socket and connect to VICI
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        # Create a VICI session with the connected socket
        session = vici.Session(sock)
        
        if debug:
            print(f"Connected to VICI interface at {host}:{port}")
        return session, sock
    except socket.error as e:
        print(f"Error connecting to VICI interface at {host}:{port}: {e}", file=sys.stderr)
        sys.exit(1)

def get_configured_connections(session: vici.Session, debug: bool) -> Dict[str, List[str]]:
    """
    Get all configured IKE connections and their child SAs.
    Returns a dictionary with IKE names as keys and lists of child names as values.
    """
    try:
        conns_list = session.list_conns()
        
        # Handle case where there are no connections
        if not conns_list:
            if debug:
                print("No configured connections found")
            return {}
        
        if debug:
            print(f"Found configurations in list_conns result")
        
        # Process the list of connections
        ike_to_children = {}
        for conn_item in conns_list:
            # Each item is a dictionary with connection name as the key
            for conn_name, conn_data in conn_item.items():
                if debug:
                    print(f"Processing connection: {conn_name}")
                
                # Get child configurations for this IKE connection
                children = []
                if "children" in conn_data:
                    children = list(conn_data["children"].keys())
                
                ike_to_children[conn_name] = children
                
                if debug:
                    print(f"IKE '{conn_name}' has {len(children)} child SAs: {', '.join(children)}")
        
        if debug:
            print(f"Processed {len(ike_to_children)} configured connections")
            
        return ike_to_children
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        print(f"Error fetching configured connections: {e}", file=sys.stderr)
        sys.exit(1)

def get_active_sas(session: vici.Session, debug: bool) -> Dict[str, Dict[str, Any]]:
    """
    Get all active IKE and Child SAs.
    Returns a nested dictionary with IKE names as outer keys and child names as inner keys.
    Values are SA status information.
    """
    try:
        sas = session.list_sas()
        active_sas = {}
        
        # Handle case where there are no SAs
        if not sas:
            if debug:
                print("No active IKE SAs found")
            return active_sas
        
        # Convert to a dictionary if it's not already
        if not isinstance(sas, dict):
            if debug:
                print("Converting list_sas result to dictionary")
            # If it's a generator or other iterable, convert it to a dictionary
            try:
                sas_dict = {}
                for item in sas:
                    if isinstance(item, tuple) and len(item) == 2:
                        key, value = item
                        sas_dict[key] = value
                    else:
                        # If the items aren't key-value pairs, just return empty
                        if debug:
                            print(f"Unexpected format in list_sas result: {item}")
                        return active_sas
                sas = sas_dict
            except (TypeError, ValueError) as e:
                if debug:
                    print(f"Error converting SA list: {e}")
                return active_sas
        
        if debug:
            print(f"Found {len(sas)} active IKE SAs")
        
        for ike_name, ike_data in sas.items():
            # Extract the actual IKE connection name (remove any unique identifiers)
            conn_name = ike_data.get("uniqueid", ike_name)
            if "remote-id" in ike_data:
                conn_name = ike_data.get("name", ike_name)
            
            children = {}
            if "child-sas" in ike_data:
                for child_name, child_data in ike_data["child-sas"].items():
                    # Extract the actual child name
                    real_child_name = child_data.get("name", child_name)
                    children[real_child_name] = child_data
            
            active_sas[conn_name] = {
                "ike_data": ike_data,
                "children": children
            }
            
            if debug:
                print(f"Active IKE '{conn_name}' has {len(children)} child SAs: {', '.join(children.keys())}")
        
        return active_sas
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        print(f"Error fetching active SAs: {e}", file=sys.stderr)
        sys.exit(1)

def supports_utf8():
    """Check if the terminal supports UTF-8 encoding."""
    try:
        # Check if the terminal encoding is UTF-8
        encoding = locale.getpreferredencoding()
        if 'UTF-8' in encoding.upper():
            return True
        
        # Check if the TERM environment variable indicates UTF-8 support
        term = os.environ.get('TERM', '')
        if 'utf' in term.lower():
            return True
        
        # Check if LANG or LC_ALL environment variables indicate UTF-8
        for env_var in ['LANG', 'LC_ALL']:
            if 'UTF-8' in os.environ.get(env_var, '').upper():
                return True
        
        return False
    except:
        return False

def get_status_symbols(use_ascii=False):
    """Get appropriate status symbols based on terminal capabilities."""
    if use_ascii or not supports_utf8():
        return {'success': '[OK]', 'failure': '[FAIL]'}
    else:
        return {'success': '[✔]', 'failure': '[✘]'}

def check_ipsec_status(configured: Dict[str, List[str]], active: Dict[str, Dict[str, Any]], 
                      debug: bool, use_ascii: bool) -> Tuple[bool, str]:
    """
    Compare configured and active SAs to generate a status report.
    Returns a tuple of (all_established, formatted_report).
    """
    all_established = True
    report_lines = []
    
    symbols = get_status_symbols(use_ascii)
    
    for ike_name, child_names in configured.items():
        # Check if IKE SA is established
        ike_established = ike_name in active
        if ike_established:
            # Check if the IKE SA is in ESTABLISHED state
            ike_state = active[ike_name]["ike_data"].get("state", "").upper()
            ike_established = ike_state == "ESTABLISHED"
        
        if ike_established:
            report_lines.append(f"{symbols['success']} {ike_name}")
        else:
            report_lines.append(f"{symbols['failure']} {ike_name}")
            all_established = False
        
        # Check child SAs
        for child_name in child_names:
            child_established = False
            if ike_established and child_name in active[ike_name]["children"]:
                child_state = active[ike_name]["children"][child_name].get("state", "").upper()
                child_established = child_state == "INSTALLED"
            
            if child_established:
                report_lines.append(f"  {symbols['success']} {child_name}")
            else:
                report_lines.append(f"  {symbols['failure']} {child_name}")
                all_established = False
    
    return all_established, "\n".join(report_lines)

def main():
    args = parse_args()
    
    # Connect to VICI interface
    session = None
    sock = None
    exit_code = 0  # Default to success
    
    try:
        # Establish connection
        session, sock = connect_to_vici(args.host, args.port, args.debug)
        
        # Get configured connections
        configured_conns = get_configured_connections(session, args.debug)
        
        # Get active SAs
        active_sas = get_active_sas(session, args.debug)
        
        # Compare and generate report
        all_established, report = check_ipsec_status(
            configured_conns, active_sas, args.debug, args.ascii
        )
        
        # Output the report
        print(report)
        
        # Always use exit code 0 for normal operation regardless of tunnel status
        exit_code = 0
        
    except KeyboardInterrupt:
        print("Operation cancelled by user", file=sys.stderr)
        exit_code = 3
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        print(f"Error: {e}", file=sys.stderr)
        exit_code = 2
    finally:
        # Clean up connections
        if sock is not None:
            try:
                sock.close()
                if args.debug:
                    print("Closed VICI socket connection")
            except:
                pass
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main()) 