# Computer Security Projects

This repository contains two projects completed for the Computer Security course. Together, they cover defensive web application security and offensive vulnerability research. Both projects are security laboratories and should only be run against the included local environments or explicitly authorized targets.

## Project 1: Securing Open eClass

Project 1 uses an intentionally old and vulnerable Open eClass 2.3 installation. The objective is to identify exploitable behavior, reproduce attacks safely, and harden the application and its Apache/PHP environment. The work analyzes and fixes common web application vulnerabilities, including:

- SQL injection
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Remote file inclusion and unsafe uploaded-file execution

The project also includes a `puppies` web application used to demonstrate a CSRF attack, Apache and PHP configuration changes, and a report describing the vulnerabilities, mitigations, and tests.

### Project 1 Security Work

- **SQL injection:** Validate numeric URL parameters with integer conversion, escape user-controlled strings, and use prepared `mysqli` statements where appropriate.
- **XSS:** Encode untrusted data with `htmlspecialchars` using quotes and UTF-8 handling before it is rendered in HTML. The report examines input from student, instructor, and administrator workflows.
- **CSRF:** Generate session-bound tokens and validate them in forms and action links. Both hidden form fields and URL parameters are covered because the application performs important actions through `href` links as well as form submissions.
- **Unsafe file handling:** Prevent directory indexing and execution of uploaded files through Apache configuration, use unpredictable names for uploaded content, and prevent students from creating assignment upload directories for assignments that do not exist.

### Project 1 Components

```text
docker-compose.yml   Apache and MySQL services
apache/               PHP/Apache image setup
conf/                 Apache, PHP, and MySQL configuration
openeclass/           Open eClass source and security changes
puppies/              Small auxiliary site used in the CSRF demonstration
```

### Running Project 1

From the `project_1` directory:

```bash
export APACHE_PORT=8001
export MYSQL_ROOT_PASSWORD=1234
docker compose up -d --build
```

Open <http://localhost:8001/> and complete the Open eClass installation wizard. Use the database host `db`, database user `root`, and the password configured in `MYSQL_ROOT_PASSWORD`.

The first build may take some time because it creates the legacy Apache/PHP image. The application is intentionally old and should not be exposed to the public internet. To restart an existing setup, use `docker compose start` after stopping it. If the Open eClass installation needs to be repeated, remove its generated configuration directory before starting the installation wizard again.

To stop the services:

```bash
docker compose stop
```

To stop and remove the containers and database volume:

```bash
docker compose down -v
```

## Project 2: Attacking a Vulnerable pico Web Server

Project 2 develops automated attacks against an intentionally vulnerable C-based pico web server. The original exercise targets a course server and is designed to be solved locally first using the matching pico source/build environment. The tasks demonstrate how implementation flaws can expose sensitive information and enable unauthorized actions:

1. Leak the MD5 digest of a plaintext password through a format-string vulnerability.
2. Recover the plaintext password through a padding-oracle attack.
3. Read `/etc/secret` through a buffer-overflow exploit.
4. Execute `lspci` and retrieve its output through a buffer-overflow exploit.

The attacks are implemented in Python and grouped by task. Shell scripts provide individual entry points, while the Docker setup copies all required scripts into a Debian-based container and runs all four tasks automatically.

### Project 2 Task Details

- **Task 1, format-string information leak:** Exploit an unsafe formatted output call in the server to read stack values and recover the MD5 digest associated with the administrator password.
- **Task 2, padding oracle:** Use the server's response to distinguish valid and invalid padding in AES-CBC ciphertexts. Reconstruct the intermediate blocks and recover the plaintext without brute-forcing the password digest.
- **Task 3, buffer overflow:** Exploit unsafe POST data handling to overwrite the stack while preserving the canary and returning into an existing server function that reads `/etc/secret`.
- **Task 4, command execution:** Reuse the same return-oriented buffer-overflow technique with the address of `system` to execute `lspci` and return its output.

The task 3 and task 4 scripts share address-discovery logic in `task3_4/sniff_addresses.py`. The payloads account for stack alignment, ASLR-derived addresses, the stack canary, and null-byte substitutions used by the vulnerable server. Because the attacks depend on the target process layout, they may need to be run against the intended compatible build and can be affected by address randomization.

### Project 2 Components

```text
Dockerfile             Reproducible attack environment
docker-run.sh          Runs tasks 1 through 4 in sequence
task1/task1.py         Format-string attack
task1/task1.sh         Task 1 entry point
task2/task2.py         Padding-oracle attack
task2/task2.sh         Task 2 entry point
task3_4/sniff_addresses.py  Address-leak and payload support
task3_4/task3.py       File-read buffer-overflow attack
task3_4/task4.py       Command-execution buffer-overflow attack
```

The scripts require Python 3 and the dependencies used by the project, including `requests`. The supplied Dockerfile installs the container dependencies automatically. A complete run can make many requests, especially for the padding-oracle task, so it may take several minutes.

### Running Project 2

From the `project_2` directory, run individual tasks with:

```bash
./task1/task1.sh
./task2/task2.sh
./task3_4/task3.sh
./task3_4/task4.sh
```

To build and run the complete attack container:

```bash
docker build --tag attack .
docker run attack
```

The attacks should be tested locally first and must not be used for denial-of-service, brute-force activity, or against systems without authorization. The course rules require a reasonable number of requests and prohibit indiscriminate scanning of the shared target.

## Repository Layout

```text
project_1/    Open eClass deployment, hardening changes, and security report
project_2/    Automated attack scripts and Docker configuration
```