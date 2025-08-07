import argparse
import csv
import sys
import html
import re
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
    ONLINE_LIBS_AVAILABLE = True
except ImportError:
    ONLINE_LIBS_AVAILABLE = False

ONLINE_EXPLANATION_CACHE = {}

def parse_message_details(message):
    if not message:
        return {}

    details = {}
    patterns = {
        'Security ID': r"(?:Security ID|ID de segurança|Identificação de segurança):\s*t?\s*([^\r\n]+)",
        'Account Name': r"(?:Account Name|Nome da conta):\s*([^\r\n]+)",
        'Logon ID': r"(?:Logon ID|ID de Logon|Identificação de logon):\s*([^\r\n]+)",
        'Process Name': r"(?:Process Name|Nome do processo):\s*([^\r\n]+)",
        'File Path': r"(?:Object Name|Nome do objeto):\s*([^\r\n]+)",
        'Logon Type': r"(?:Logon Type|Tipo de Logon):\s*([^\r\n]+)"
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            details[key] = match.group(1).strip()

    return details

def lookup_event_id_online(event_id):
    if not ONLINE_LIBS_AVAILABLE:
        return None

    url = f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"
    print(f"  [i] Looking up Event ID {event_id} online...")

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        description_tag = soup.find('p')
        if description_tag and description_tag.text:
            return description_tag.text.strip()
        return "No explanation found for this Event ID on the online database."

    except requests.exceptions.RequestException as e:
        print(f"  [!] Warning: Could not connect to online database. {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] Warning: Failed to parse online explanation. {e}", file=sys.stderr)
        return None

def process_events(events, perform_online_lookup):
    processed = []
    if not events:
        return []

    print("[*] Processing events, parsing details, and fetching explanations...")
    for event in events:
        new_event = event.copy()
        message = new_event.get('Message', '')
        details = parse_message_details(message)
        new_event.update(details)
        event_id = new_event.get('EventID')
        explanation = None
        if perform_online_lookup and event_id:
            explanation = ONLINE_EXPLANATION_CACHE.get(str(event_id))
            if not explanation:
                explanation = lookup_event_id_online(str(event_id))
                if explanation:
                    ONLINE_EXPLANATION_CACHE[str(event_id)] = explanation

        new_event['Explanation'] = explanation or "N/A"
        processed.append(new_event)
    return processed

def read_from_csv(file_path, limit, level_filters, id_filters, search_term):
    events = []
    print(f"[*] Reading and parsing non-standard CSV file: {file_path}")
    try:
        with open(file_path, mode='r', encoding='utf-8') as f:
            header_line = next(f)
            content = f.read()

        event_records = re.split(r'\r?\n(?=Sucesso da Auditoria|Falha da Auditoria|Information|Warning|Error|Critical)', content)

        for record in event_records:
            if not record.strip():
                continue

            if len(events) >= limit:
                break

            match = re.match(r'([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),(.*)', record, re.DOTALL)

            if not match:
                continue

            parts = match.groups()

            message = parts[5].strip()
            if message.startswith('"') and message.endswith('"'):
                message = message[1:-1]

            row = {
                'Level': parts[0].strip(),
                'Timestamp': parts[1].strip(),
                'Provider': parts[2].strip(),
                'EventID': parts[3].strip(),
                'Message': message
            }

            try:
                add_event = True
                if level_filters and row.get('Level', '').lower() not in level_filters: add_event = False
                if id_filters and int(row.get('EventID', '0')) not in id_filters: add_event = False
                if search_term and search_term.lower() not in row.get('Message', '').lower(): add_event = False
                if add_event:
                    events.append(row)
            except (ValueError, TypeError):
                print(f"[!] Warning: Skipping malformed row in CSV: {row}", file=sys.stderr)
                continue

    except FileNotFoundError:
        print(f"[!] Error: File not found at {file_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: Failed to read or parse CSV file. {e}", file=sys.stderr)
        sys.exit(1)
    return events

def print_events_terminal(events):
    if not events:
        print("\n[*] No events found matching the criteria.")
        return

    print(f"\n[*] Displaying {len(events)} event(s):\n")
    for event in events:
        print("-" * 80)
        print(f"  Timestamp: {event.get('Timestamp', 'N/A')}")
        print(f"  Level:     {event.get('Level', 'N/A')}")
        print(f"  Event ID:  {event.get('EventID', 'N/A')}")
        if event.get('Explanation') and event.get('Explanation') != 'N/A':
            print(f"  Meaning:   {event.get('Explanation')}")
        print(f"  Account:   {event.get('Account Name', 'N/A')} (SID: {event.get('Security ID', 'N/A')})")
        if event.get('File Path'):
            print(f"  File Path: {event.get('File Path')}")
        if event.get('Process Name'):
            print(f"  Process:   {event.get('Process Name')}")
        print(f"  Message:   {event.get('Message', 'N/A')}")
    print("-" * 80)

def export_to_html(events, filename):
    if not events:
        print("\n[*] No events to export to HTML.")
        return

    print(f"\n[*] Generating interactive HTML report at {filename}...")

    styles_and_script = """
    <style>
        :root {
            --bg-color: #f4f7f9; --text-color: #333; --container-bg: #fff;
            --header-bg: #2c3e50; --header-color: #fff; --border-color: #ddd;
            --row-alt-bg: #f2f2f2; --row-hover-bg: #e8f4fd; --row-active-bg: #d1e9fc;
            --details-bg: #fafafa; --details-text: #555; --shadow-color: rgba(0,0,0,0.1);
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-color: #1a1a1a; --text-color: #e0e0e0; --container-bg: #2c2c2c;
                --header-bg: #1f2937; --header-color: #fff; --border-color: #444;
                --row-alt-bg: #333; --row-hover-bg: #3a4149; --row-active-bg: #4a5159;
                --details-bg: #222; --details-text: #ccc; --shadow-color: rgba(0,0,0,0.4);
            }
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: var(--bg-color); color: var(--text-color); }
        .container { max-width: 1400px; margin: 20px auto; padding: 20px; background-color: var(--container-bg); box-shadow: 0 2px 10px var(--shadow-color); border-radius: 8px; }
        h1 { color: var(--text-color); border-bottom: 2px solid var(--border-color); padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { background-color: var(--header-bg); color: var(--header-color); }
        .summary-row { cursor: pointer; }
        .summary-row:nth-child(even) { background-color: var(--row-alt-bg); }
        .summary-row:hover { background-color: var(--row-hover-bg); }
        .summary-row.active { background-color: var(--row-active-bg); }
        .details-row { display: none; }
        .details-cell { background-color: var(--details-bg); padding: 20px; }
        .details-cell pre { white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.9em; color: var(--details-text); }
        .level { font-weight: bold; }
        .level-critical, .level-error { color: #e74c3c; }
        .level-warning { color: #f39c12; }
        .level-information { color: #3498db; }
        .level-verbose, .level-logalways, .level-sucesso-da-auditoria { color: #7f8c8d; }
        .details, .explanation { word-break: break-word; font-size: 0.9em; }
        .details strong { color: var(--text-color); }
    </style>
    <script>
        function toggleDetails(index) {
            var detailsRow = document.getElementById('details-' + index);
            var summaryRow = document.getElementById('summary-' + index);
            if (detailsRow.style.display === 'table-row') {
                detailsRow.style.display = 'none';
                summaryRow.classList.remove('active');
            } else {
                detailsRow.style.display = 'table-row';
                summaryRow.classList.add('active');
            }
        }
    </script>
    """

    level_class_map = {
        'critical': 'level-critical', 'error': 'level-error', 'warning': 'level-warning',
        'information': 'level-information', 'verbose': 'level-verbose', 'logalways': 'level-logalways',
        'sucesso da auditoria': 'level-sucesso-da-auditoria'
    }

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n<title>Interactive Event Log Report</title>\n{styles_and_script}\n</head>\n<body>\n")
            f.write("<div class='container'>\n")
            f.write(f"<h1>Interactive Event Log Report</h1>\n<p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. Click on a row to see the full event message.</p>\n")
            f.write("<table>\n")
            f.write("<thead><tr><th>Timestamp</th><th>Level</th><th>Event ID</th><th>Details</th><th class='explanation'>Explanation</th></tr></thead>\n")
            f.write("<tbody>\n")

            for i, event in enumerate(events):
                level_str = event.get('Level', 'N/A').lower()
                level_class = level_class_map.get(level_str, '')

                ts = html.escape(event.get('Timestamp', 'N/A'))
                eid = html.escape(event.get('EventID', 'N/A'))
                explanation = html.escape(event.get('Explanation', 'N/A'))
                full_message = html.escape(event.get('Message', 'N/A'))

                details_html = ""
                if event.get('Account Name'): details_html += f"<strong>Account:</strong> {html.escape(event.get('Account Name'))}<br>"
                if event.get('Security ID'): details_html += f"<strong>SID:</strong> {html.escape(event.get('Security ID'))}<br>"
                if event.get('Process Name'): details_html += f"<strong>Process:</strong> {html.escape(event.get('Process Name'))}<br>"
                if event.get('File Path'): details_html += f"<strong>File:</strong> {html.escape(event.get('File Path'))}"

                f.write(f"<tr id='summary-{i}' class='summary-row' onclick='toggleDetails({i})'>\n")
                f.write(f"<td>{ts}</td>\n")
                f.write(f"<td><span class='level {level_class}'>{level_str.capitalize()}</span></td>\n")
                f.write(f"<td>{eid}</td>\n")
                f.write(f"<td class='details'>{details_html}</td>\n")
                f.write(f"<td class='explanation'>{explanation}</td>\n")
                f.write("</tr>\n")

                f.write(f"<tr id='details-{i}' class='details-row'>\n")
                f.write(f"<td colspan='5' class='details-cell'><pre><strong>Full Message:</strong>\n{full_message}</pre></td>\n")
                f.write("</tr>\n")

            f.write("</tbody>\n</table>\n</div>\n</body>\n</html>")
        print(f"[*] Successfully generated interactive HTML report: {filename}")
    except IOError as e:
        print(f"[!] Error: Could not write to HTML file {filename}. {e}", file=sys.stderr)

def export_to_csv(events, filename):
    if not events:
        print("\n[*] No events to export.")
        return
    print(f"\n[*] Exporting {len(events)} event(s) to {filename}...")
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            all_keys = set()
            for event in events:
                all_keys.update(event.keys())
            fieldnames = sorted(list(all_keys))

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(events)
        print(f"[*] Successfully exported to {filename}")
    except IOError as e:
        print(f"[!] Error: Could not write to file {filename}. {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="A tool to filter and analyze Windows Event Logs from .csv files, with online lookup for Event IDs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('file', type=str, help="Path to the .csv log file to read from.")
    level_choices = ['critical', 'error', 'warning', 'information', 'verbose', 'logalways', 'sucesso da auditoria']
    parser.add_argument('--level', nargs='+', choices=level_choices, help="Filter by event level(s).")
    parser.add_argument('--id', nargs='+', type=int, help="Filter by one or more Event IDs.")
    parser.add_argument('--search', type=str, help="A keyword to search for within the event message.")
    parser.add_argument('--limit', type=int, default=50, help="Maximum number of events to retrieve.\nDefault: 50.")

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument('--csv', type=str, help="Export filtered results to a CSV file.")
    output_group.add_argument('--html', type=str, help="Generate a friendly HTML report of the results.")

    parser.add_argument('--no-online-lookup', action='store_true', help="Disable the online lookup feature for Event IDs.")

    args = parser.parse_args()

    perform_online_lookup = not args.no_online_lookup
    if perform_online_lookup and not ONLINE_LIBS_AVAILABLE:
        print("[!] Warning: 'requests' and 'beautifulsoup4' are not installed. Online lookup is disabled.", file=sys.stderr)
        print("          To enable it, run: pip install requests beautifulsoup4", file=sys.stderr)
        perform_online_lookup = False

    if not args.file.lower().endswith('.csv'):
        print(f"[!] Error: The input file must be a .csv file. Provided: {args.file}", file=sys.stderr)
        sys.exit(1)

    raw_events = read_from_csv(args.file, args.limit, args.level or [], args.id or [], args.search)

    processed_events = process_events(raw_events, perform_online_lookup)

    if args.csv:
        export_to_csv(processed_events, args.csv)
    elif args.html:
        export_to_html(processed_events, args.html)
    else:
        print_events_terminal(processed_events)

if __name__ == "__main__":
    main()