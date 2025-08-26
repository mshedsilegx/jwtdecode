# JWT Decode Application

## Purpose
The `jwtdecode` application is a command-line utility designed to parse JSON Web Tokens (JWTs) and extract their claims. It provides flexible options for inputting the JWT token (as a string, from a file, or from an environment variable) and for formatting and saving the output (JSON, CSV, or XML).

## Command-Line Parameters

The application supports the following command-line flags:

*   `-token-string <string>`: Directly provides the JWT token as a string.
*   `-token-file <file_path>`: Specifies a file from which to read the JWT token. The file should contain the token as plain text.
*   `-token-env`: Instructs the application to read the JWT token from the `JWT_TOKEN` environment variable.

    **Note:** `-token-string`, `-token-file`, and `-token-env` are mutually exclusive. Only one of these options can be used at a time.

*   `-output-format <format>`: Specifies the desired output format for the JWT claims.
    *   Accepted values: `JSON`, `CSV`, `XML`.
    *   Default: `JSON` if not specified.
*   `-output-file <file_path>`: Specifies the full path where the formatted output should be saved.
    *   Default: `claims.<format_extension>` (e.g., `claims.json`, `claims.csv`, `claims.xml`) in the current directory if not specified.
*   `-config <file_path>`: Specifies a JSON configuration file to define application parameters.
    *   **Important:** If `-config` is used, it must be the *sole* argument. No other command-line flags (including token input, output format, or output file) can be present.
*   `-version`: Displays the current version of the application and exits.
*   `-convert-epoch`: A boolean flag that, if set, converts Unix epoch timestamps found in the JWT claims (e.g., `iat`, `exp`, `nbf`) into human-readable date and time strings in the output.
*   `-silent`: A boolean flag that, if set, suppresses all non-error output messages from the application.
*   `-max-token-size <int>`: Sets the maximum allowed size for the JWT token in megabytes (MB). Tokens exceeding this size will result in an error.
    *   Default: `1` MB.
*   `-max-output-size <int>`: Sets the maximum allowed size for the formatted output in megabytes (MB). Output exceeding this size will result in an error.
    *   Default: `100` MB.

## Configuration File Structure (`config.json`)

The `config.json` file allows you to define all application parameters in a structured JSON format.

```json
{
  "jwtToken": "your_jwt_token_string_or_path_or_env_var_name",
  "tokenType": "string",
  "outputFormat": "JSON",
  "outputFile": "claims.json",
  "convertEpoch": true,
  "silentExec": false,
  "maxTokenSizeMB": 1,
  "maxOutputSizeMB": 100
}
```

### Field Descriptions:

*   `jwtToken` (string):
    *   If `tokenType` is "string": The actual JWT token string.
    *   If `tokenType` is "file": The full path to a file containing the JWT token.
    *   If `tokenType` is "environment": The name of the environment variable from which to read the JWT token. If this field is empty, it defaults to `JWT_TOKEN`.
    *   **Mandatory:** Yes, unless `tokenType` is "environment" and you intend to use the default `JWT_TOKEN` environment variable.
*   `tokenType` (string): Specifies how the `jwtToken` field should be interpreted.
    *   Accepted values: `"string"`, `"file"`, `"environment"`.
    *   **Optional:** Defaults to `"string"` if `jwtToken` is provided and `tokenType` is not specified. If `jwtToken` is empty, `tokenType` must be specified (typically as `"environment"`).
*   `outputFormat` (string): Same as the `-output-format` command-line parameter.
    *   **Optional:** Defaults to `"JSON"`.
*   `outputFile` (string): Same as the `-output-file` command-line parameter.
    *   **Optional:** Defaults to `claims.<format_extension>` based on `outputFormat`.
*   `convertEpoch` (boolean): Same as the `-convert-epoch` command-line parameter.
    *   **Optional:** Defaults to `false`.
*   `silentExec` (boolean): Same as the `-silent` command-line parameter.
    *   **Optional:** Defaults to `false`.
*   `maxTokenSizeMB` (integer): Same as the `-max-token-size` command-line parameter.
    *   **Optional:** Defaults to `1`.
*   `maxOutputSizeMB` (integer): Same as the `-max-output-size` command-line parameter.
    *   **Optional:** Defaults to `100`.

## Architectural Guidelines

This application was developed following a set of strict architectural guidelines to ensure quality, maintainability, and security. These include:

1.  **Step-by-Step Planning:** Thorough planning and architectural design before coding.
2.  **Safe Modifications:** Avoiding `replace` for complex, multi-line code changes; preferring `write_file` to prevent errors and ensure stability.
3.  **File Backups:** Creating timestamped backups of existing files before any modifications.
4.  **Systematic Validation:** Rigorous code validation at every step using `go fmt`, `go vet`, `golangci-lint`, and `govulncheck` before building.
5.  **Problem Decomposition:** Breaking down complex problems into smaller, manageable units, validating each before integration.
6.  **Automated Versioning:** Implementing a consistent build process that increments the application version (e.g., `0.0.1` to `0.0.2`) and appends a `YYYYMMDD` datestamp using `ldflags`.
7.  **Standard Arguments:** Adhering to common CLI argument conventions (`-version`, `-silent`, `-config`).
8.  **Platform-Specific EOLs:** Ensuring correct end-of-line terminations (`\r\n` for Windows, `\n` for Linux) for cross-platform compatibility.
9.  **Plan-Communicate-Approve Cycle:** Always thinking, using tools, planning, and communicating the plan for approval before implementing code.
10. **Codebase Analysis & Improvements:** Performing deep analysis of the generated codebase for recommendations and improvements, subject to approval.
11. **Security Analysis & Sanitization:** Conducting security reviews and ensuring all user inputs are properly sanitized and secured to prevent malicious injections (e.g., `sanitizeFilePath`, `escapeCSVValue`).
