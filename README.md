# Event Log Analyzer

> An advanced, cross-platform Python tool for parsing, filtering, and analyzing Windows Event Logs from `.csv` files. It transforms raw log data into an interactive, user-friendly HTML report with automatic online lookup for Event ID explanations.

## Features

* **Interactive HTML Reports:** Generates a clean, modern, and interactive HTML report with a dark mode that respects your OS settings.
* **Intelligent Parsing:** Automatically parses non-standard `.csv` files exported from the Windows Event Viewer, correctly handling multi-line messages.
* **Detailed Extraction:** Intelligently pulls key details from event messages, such as **Account Names**, **Security IDs (SIDs)**, and **Process Names**.
* **Live Explanations:** Looks up Event IDs in real-time to provide up-to-date, comprehensive explanations.
* **Powerful Filtering:** Allows you to filter events by `level`, `Event ID`, and `keywords`.
* **Cross-Platform:** The script is fully compatible with **Windows**, **macOS**, and **Linux**.

## Requirements

* Python 3.6+
* The `requests` and `beautifulsoup4` libraries.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <your-repository-name>
    ```

2.  **Install the required libraries from `requirements.txt`:**
    ```bash
    pip install -r requirements.txt
    ```

## ⚙️ How to Use

The script is run from the command line. The only required argument is the path to the `.csv` log file.

#### Basic Example

To generate an HTML report from your log file, use the `--html` flag:

```bash
python event_log_analyzer.py "C:\path\to\your\security-logs.csv" --html report.html
```

#### Advanced Filtering
You can combine flags to narrow down your analysis. This command finds all failed logon attempts (ID 4625) and creates a report:
```bash
python event_log_analyzer.py security-logs.csv --id 4625 --level "Falha da Auditoria" --html failed_logons.html
```

#### Command-Line Parameters

| Parameter                | Description                                                | Example                                    |
| ------------------------ | ---------------------------------------------------------- | ------------------------------------------ |
| `file`                   | **(Required)** The path to the `.csv` log file.            | `security-logs.csv`                        |
| `--html <filename>`      | Generate an interactive HTML report.                       | `--html report.html`                       |
| `--csv <filename>`       | Export the filtered results to a new CSV file.             | `--csv filtered.csv`                       |
| `--level <level>`        | Filter by one or more event levels.                        | `--level error warning`                    |
| `--id <id>`              | Filter by one or more Event IDs.                           | `--id 4624 4625`                           |
| `--search <term>`        | Search for a keyword in the event message.                 | `--search "Administrator"`                 |
| `--limit <number>`       | Set the maximum number of events to process.               | `--limit 100`                              |
| `--no-online-lookup`     | Disable the online lookup for Event ID explanations.       | `--no-online-lookup`                       |

