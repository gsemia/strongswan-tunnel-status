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
                print("[CONFIG] No configured connections found")
            return {}
        
        if debug:
            print(f"[CONFIG] Found configurations in list_conns result")
        
        # Process the list of connections
        ike_to_children = {}
        for conn_item in conns_list:
            # Each item is a dictionary with connection name as the key
            for conn_name, conn_data in conn_item.items():
                if debug:
                    print(f"[CONFIG] Processing connection: {conn_name}")
                
                # Get child configurations for this IKE connection
                children = []
                if "children" in conn_data:
                    children = list(conn_data["children"].keys())
                
                ike_to_children[conn_name] = children
                
                if debug:
                    print(f"[CONFIG] IKE '{conn_name}' has {len(children)} child SAs: {', '.join(children)}")
        
        if debug:
            print(f"[CONFIG] Processed {len(ike_to_children)} configured connections")
            
        return ike_to_children
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        print(f"[CONFIG] Error fetching configured connections: {e}", file=sys.stderr)
        sys.exit(1)

def decode_if_bytes(value):
    """Convert bytes to string if needed."""
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return str(value)
    return value

def get_active_sas(session: vici.Session, debug: bool) -> Dict[str, Dict[str, Any]]:
    """
    Get all active IKE and Child SAs.
    Returns a nested dictionary with IKE names as outer keys and child names as inner keys.
    Values are SA status information.
    """
    try:
        sas_list = session.list_sas()
        active_sas = {}
        
        # Handle case where there are no SAs
        if not sas_list:
            if debug:
                print("[SAs] No active IKE SAs found")
            return active_sas
        
        if debug:
            print(f"[SAs] Found active SAs in list_sas result")
        
        # Process the list of SAs
        for sa_item in sas_list:
            # Each item is a dictionary with SA name as the key
            for ike_name_raw, ike_data in sa_item.items():
                # Decode bytes to string if needed
                ike_name = decode_if_bytes(ike_name_raw)
                
                if debug:
                    print(f"[SAs] Processing IKE SA: {ike_name}")
                
                # Always use the name field if available, otherwise fallback to ike_name
                conn_name = ike_name
                if "name" in ike_data:
                    conn_name = decode_if_bytes(ike_data.get("name"))
                    if debug:
                        print(f"[SAs] Using name '{conn_name}' for connection")
                        if "uniqueid" in ike_data:
                            unique_id = decode_if_bytes(ike_data.get("uniqueid"))
                            print(f"[SAs] Ignoring uniqueid '{unique_id}'")
                
                children = {}
                if "child-sas" in ike_data:
                    for child_name_raw, child_data in ike_data["child-sas"].items():
                        # Decode bytes to string if needed
                        child_name = decode_if_bytes(child_name_raw)
                        
                        # Always use the name field if available for child SAs
                        real_child_name = child_name
                        if "name" in child_data:
                            real_child_name = decode_if_bytes(child_data.get("name"))
                            if debug and real_child_name != child_name:
                                print(f"[SAs] Using name '{real_child_name}' for child SA (instead of '{child_name}')")
                        
                        children[real_child_name] = child_data
                
                # Handle duplicate names by appending counters
                if conn_name in active_sas:
                    if debug:
                        print(f"[SAs] Warning: Duplicate connection name '{conn_name}', using only the first instance")
                    continue
                
                active_sas[conn_name] = {
                    "ike_data": ike_data,
                    "children": children
                }
                
                if debug:
                    # Safely join the keys as strings
                    child_names = [str(k) for k in children.keys()]
                    child_list = ", ".join(child_names) if child_names else "none"
                    print(f"[SAs] Active IKE '{conn_name}' has {len(children)} child SAs: {child_list}")
        
        if debug:
            print(f"[SAs] Processed {len(active_sas)} active IKE SAs")
            conn_names = list(active_sas.keys())
            print(f"[SAs] Active connection names: {conn_names}")
            
        return active_sas
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        print(f"[SAs] Error fetching active SAs: {e}", file=sys.stderr)
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
    
    if debug:
        print(f"[STATUS] Checking {len(configured)} configured vs {len(active)} active IKE SAs")
        print(f"[STATUS] Active connection names: {list(active.keys())}")
    
    for ike_name, child_names in configured.items():
        # Try direct match first
        ike_established = ike_name in active
        
        # If no direct match, try case-insensitive match
        active_conn_name = None
        if not ike_established:
            for active_name in active.keys():
                if ike_name.lower() == active_name.lower():
                    ike_established = True
                    active_conn_name = active_name
                    if debug:
                        print(f"[STATUS] Found case-insensitive match for {ike_name} -> {active_name}")
                    break
        else:
            active_conn_name = ike_name
        
        if ike_established:
            # Check if the IKE SA is in ESTABLISHED state
            ike_state = active[active_conn_name]["ike_data"].get("state", "")
            if isinstance(ike_state, bytes):
                ike_state = ike_state.decode('utf-8', errors='replace')
            ike_state = ike_state.upper()
            
            ike_established = ike_state == "ESTABLISHED"
            
            if debug:
                print(f"[STATUS] IKE '{ike_name}' state: {ike_state} -> established: {ike_established}")
        
        if ike_established:
            report_lines.append(f"{symbols['success']} {ike_name}")
        else:
            report_lines.append(f"{symbols['failure']} {ike_name}")
            all_established = False
            if debug:
                print(f"[STATUS] IKE '{ike_name}' not found or not established")
        
        # Check child SAs
        for child_name in child_names:
            child_established = False
            
            if ike_established:
                # Try direct match for child SA
                child_in_active = child_name in active[active_conn_name]["children"]
                active_child_name = None
                
                # If no direct match, try case-insensitive match
                if not child_in_active:
                    for active_child in active[active_conn_name]["children"].keys():
                        if child_name.lower() == active_child.lower():
                            child_in_active = True
                            active_child_name = active_child
                            if debug:
                                print(f"[STATUS] Found case-insensitive match for child {child_name} -> {active_child}")
                            break
                else:
                    active_child_name = child_name
                
                if child_in_active:
                    # Check if the child SA is in INSTALLED state
                    child_state = active[active_conn_name]["children"][active_child_name].get("state", "")
                    if isinstance(child_state, bytes):
                        child_state = child_state.decode('utf-8', errors='replace')
                    child_state = child_state.upper()
                    
                    child_established = child_state == "INSTALLED"
                    
                    if debug:
                        print(f"[STATUS] Child '{child_name}' state: {child_state} -> established: {child_established}")
            
            if child_established:
                report_lines.append(f"  {symbols['success']} {child_name}")
            else:
                report_lines.append(f"  {symbols['failure']} {child_name}")
                all_established = False
                if debug:
                    if not ike_established:
                        print(f"[STATUS] Child '{child_name}' not established because parent IKE is down")
                    else:
                        print(f"[STATUS] Child '{child_name}' not found or not installed")
    
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