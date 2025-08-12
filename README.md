## Quarantine-Malicious-Binary.sh

This script quarantines a specified malicious binary by moving it to a secure quarantine directory, providing a JSON-formatted output for integration with your SIEM.

### Overview

The `Quarantine-Malicious-Binary.sh` script moves a specified file to `/var/ossec/quarantine`, disables execution permissions, and records SHA256 hashes before and after the move. It logs all actions and outputs the result in JSON format for active response workflows.

### Script Details

#### Core Features

1. **File Quarantine**: Moves the specified file to a quarantine directory.
2. **Hash Verification**: Records SHA256 hashes before and after quarantine.
3. **Permission Restriction**: Removes execute permissions from the quarantined file.
4. **JSON Output**: Generates a structured JSON report for integration with security tools.
5. **Logging Framework**: Provides detailed logs for script execution.
6. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
ARG1="/path/to/malicious_binary" ./Quarantine-Malicious-Binary.sh
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `ARG1`    | string | The path to the file to quarantine (required) |
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` (output JSON log) |
| `LogPath` | string | `/tmp/Quarantine-Malicious-Binary.sh-script.log` (detailed execution log) |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Rotates the detailed log file if it exceeds the size limit
- Clears the active response log file
- Logs the start of the script execution

#### 2. Quarantine Logic
- Checks if the file exists and is specified
- Moves the file to `/var/ossec/quarantine`
- Removes execute permissions from the quarantined file
- Records SHA256 hashes before and after the move
- Logs the result and status

#### 3. JSON Output Generation
- Formats the result into a JSON object
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Quarantine-Malicious-Binary.sh",
  "data": {
    "original_path": "/tmp/malware",
    "quarantine_path": "/var/ossec/quarantine/malware.20250718103045.quarantine",
    "sha256_before": "abcdef123456...",
    "sha256_after": "abcdef123456..."
  },
  "copilot_soar": true
}
```

#### Error Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Quarantine-Malicious-Binary.sh",
  "status": "error",
  "error": "No file specified or not found: /tmp/missing_file",
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to move and modify files
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files and quarantine directory

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has privileges to move and modify files
2. **Missing File**: Provide the file path via the `ARG1` environment variable
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ARG1="/path/to/malicious_binary" ./Quarantine-Malicious-Binary.sh
```

### Contributing

When modifying this script:
1. Maintain the quarantine logic and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
