## Donate 🙏🏻💚
- **We invite you to support the IPv6Spot project, aimed at enhancing public network security through IPv6 technology. Donate to our Bitcoin wallet, and thank you to everyone who contributes:**
- Network:Bitcoin, Deposit Address: `17w2iiZevtWzRyQeSYhrBWrhCyQmKBqzVx`
- Binance ID: `1004306965`

## IPv6Spot Project Overview

- The IPv6Spot project is the culmination of over two years of continuous work, and I am thrilled to share its progress with you. The key focus has been on addressing the challenges associated with handling temporary and multiple IPv6 addresses, which we successfully resolved through the use of MAC addresses. This approach proved to be an ideal solution, operating seamlessly without issues.
- This captive portal project using IPv6 stands as the first of its kind worldwide, and I am delighted to announce that we have managed to overcome all hurdles to ensure that the captive portal operates smoothly with IPv6, all without relying on a DHCP server. This solution is especially beneficial, as certain systems, like Android, do not support DHCP for IPv6.
- I hope this innovation resonates with you and showcases the potential of IPv6 for secure and user-friendly network experiences.
- Some may ask, "Why transition from IPv4 to IPv6?" When using a captive portal with IPv4, it is relatively easy to breach devices via their MAC address and gain internet access by using another person's active session data. However, with IPv6, this is no longer possible.
- **Project start date: 06/2021**
- **📌 important note: The IPv6 addresses used in the source code are for the example only, you must replace them with addresses compatible with the IPv6 standards.**

## 💽 IPv6Spot installation
- **💽 IPv6Spot installation guide with iso file download link to install the system:**
- Link 1 [installation guide](https://youtu.be/Iejz8vUP9wY?si=NBwTcxjhvVZ8RIn_)
- Link 2 [iso file download link](https://drive.google.com/file/d/1aDe7ILiZPsQL_ZeCsoAG2Kg7vWE2YxC3/view?pli=1)
- 📌 Currently, the IPv6Spot system operates on the x86_64 architecture, with plans for future development to support additional architectures.

Screenshots of IPv6Spot System Installation:
<p align="left">
  <img src="images/9.png" width="100" height="100">
  <img src="images/10.png" width="100" height="100">
</p>
Screenshots of IPv6Spot System:
<p align="left">
  <img src="images/101.png" width="100" height="100">
  <img src="images/102.png" width="100" height="100">
  <img src="images/103.png" width="100" height="100">
  <img src="images/104.png" width="100" height="100">
  <img src="images/105.png" width="100" height="100">
  <img src="images/106.png" width="100" height="100">
  <img src="images/107.png" width="100" height="100">
  <img src="images/108.png" width="100" height="100">
  <img src="images/109.png" width="100" height="100">
  <img src="images/110.png" width="100" height="100">
  <img src="images/111.png" width="100" height="100">
  <img src="images/112.png" width="100" height="100">
  <img src="images/113.png" width="100" height="100">
  <img src="images/114.png" width="100" height="100">
  <img src="images/115.png" width="100" height="100">
  <img src="images/116.png" width="100" height="100">
</p>
Screenshots of user login using the captive portal:
<p align="left">
  <img src="images/117.jpg" width="100" height="100">
  <img src="images/118.jpg" width="100" height="100">
  <img src="images/119.jpg" width="100" height="100">
  <img src="images/120.jpg" width="100" height="100">
  <img src="images/121.jpg" width="100" height="100">
  <img src="images/122.jpg" width="100" height="100">
  <img src="images/123.jpg" width="100" height="100">
</p>

## License ⚖️
ipv6spot" Project License Agreement, See the [LICENSE](./LICENSE) file for more details.

1. Non-Commercial Use
The "ipv6spot" project is licensed free of charge for personal, educational, or research purposes that are non-commercial. You may download, modify, and distribute the source code for these purposes without the need for permission or payment.

2. Commercial Use
Any use of the project in a commercial or profit-making environment, including incorporating it into products or services that are sold or used for profit, requires the purchase of a commercial license. Commercial use includes, but is not limited to:

Integrating the project into a product or service that is sold or generates revenue.
Offering the project as a paid service or part of a paid service.
Any use within a commercial organization, whether internal or external.
To obtain a commercial license, please contact abdulkader.alrezej@gmail.com to arrange the purchase and discuss terms.
4. General Terms
All intellectual property rights related to the "ipv6spot" project are reserved by the project owner Abdulkader Alrezej.
You may not remove any copyright notices or modify the attribution in the source code.
The project is provided "as-is," without any express or implied warranties.
5. Penalties
Any unauthorized commercial use of the project without purchasing a license will be considered a violation of this agreement and may result in legal action.

## Research Paper 🗒️  
**Research Paper:** *IPv6Spot - An Innovative IPv6 Captive Portal Solution with Integrated DNS and Proxy Services*

---

### Abstract  
This paper introduces IPv6Spot, a pioneering captive portal system designed exclusively for IPv6 networks. Developed by Abdulkader Alrezej, IPv6Spot addresses the critical need for effective network access control in IPv6 environments. The system offers comprehensive features such as user authentication, dynamic IP and MAC address management, bandwidth control, usage monitoring, integrated DNS redirection, and custom proxy servers. The inclusion of custom DNS and proxy servers enhances the captive portal functionality by intercepting network requests and guiding unauthenticated users to the login page. This paper provides an in-depth examination of the system's architecture, implementation details, and the innovative approaches employed to manage IPv6 network access effectively.

---

### Introduction  
The global transition to IPv6 is necessitated by the exhaustion of IPv4 addresses and the growing number of internet-connected devices. Despite this shift, many network management tools and captive portal solutions remain focused on IPv4, leaving a gap in support for IPv6 networks. IPv6Spot fills this gap by providing a fully functional captive portal tailored for IPv6 environments. The system not only controls network access but also integrates custom DNS and proxy servers to enhance user experience and enforce network policies effectively.

---

### Project Overview  
**IPv6Spot** is a Python-based application utilizing the Flask web framework, various Linux networking utilities, a custom DNS server, and proxy servers. Key features of IPv6Spot include:

1. **IPv6 Captive Portal with DNS and Proxy Redirection:** Redirects unauthenticated users to a login page by intercepting DNS queries and HTTP requests, controlling network access.
2. **Secure User Authentication:** Implements robust authentication mechanisms with hashed passwords and secure session management.
3. **Dynamic IP and MAC Address Management:** Automatically detects and manages user devices based on their IPv6 addresses and MAC addresses.
4. **Bandwidth Control and Traffic Shaping:** Utilizes Linux traffic control (`tc`) to allocate and limit bandwidth per user.
5. **Usage Monitoring and Enforcement:** Tracks data usage and session duration, enforcing limits based on predefined user policies.
6. **Custom DNS and Proxy Server Integration:** Employs DNS and proxy servers to manage network requests, enhancing captive portal functionality.

---

### System Architecture  
The architecture of IPv6Spot is modular, comprising several interconnected components that work together to manage network access and enforce policies.

#### Web Interface  
- **Flask Framework:** Manages HTTP requests, user sessions, and renders templates for the web interface.
- **Templates and Static Files:** Provide the user interface elements such as login pages and dashboards.

#### Networking Layer  
- **IP and MAC Address Management:** Utilizes system commands and the `ipaddress` module to manage IPv6 addresses and associate them with user sessions.
- **Traffic Control:** Implements bandwidth limitations and traffic shaping using the `tc` command.
- **Firewall Rules:** Uses `ip6tables` and `nftables` to enforce network access policies.

#### Database Layer  
- **SQLite Database:** Stores user credentials, session data, IP addresses, and usage statistics.
- **Schema Management:** Ensures the database schema supports all required fields for new features.

#### Custom DNS Server  
- **DNS Interception:** A DNS server built with the `dnslib` library intercepts DNS queries from clients.
- **Domain Redirection:** Redirects specific DNS queries to the captive portal or blocks them based on the client's authentication status.
- **IPv4-to-IPv6 Translation:** Converts IPv4 addresses to IPv6 format for domains that do not have IPv6 records.

#### Custom Proxy Servers  
- **HTTP Proxy Server:** Intercepts HTTP requests from clients and redirects unauthenticated users to the captive portal.
- **Network Detection Responses:** Provides appropriate responses to network connectivity checks performed by operating systems.

#### Background Services  
- **Periodic IP Checks:** Monitors user activity and enforces policies through background threads.
- **Usage Data Collection:** Continuously updates usage statistics.

---

### Implementation Details  
The implementation of IPv6Spot involves integrating Python scripts with system-level networking commands, a custom DNS server, and custom proxy servers.

#### User Authentication  
- **Credential Security:** Uses `werkzeug.security` for password hashing and verification.
- **Session Handling:** Manages user sessions securely using Flask's session management and secret keys.

#### IP and MAC Address Management  
- **MAC Address Retrieval:** Executes `ip -6 nei` to map IPv6 addresses to MAC addresses.
- **Dynamic IP Handling:** Adds or removes IPv6 addresses in `nftables` based on user authentication status.

#### Traffic Control  
- **Bandwidth Allocation:** Creates `tc` classes and filters to enforce per-user bandwidth limits.
- **Dynamic Adjustment:** Updates `tc` rules in response to changes in user sessions.

#### Firewall and Access Control  
- **Firewall Configuration:** Manages `ip6tables` rules to control traffic based on user authentication.
- **Nftables Integration:** Uses `nftables` for advanced packet filtering and accounting.

---

### Custom DNS Server  
The custom DNS server is a critical component that enhances the captive portal's functionality.

#### DNS Server Overview  
- **Library Used:** Built using the `dnslib` Python library, which allows the creation of custom DNS servers and resolvers.
- **Server Initialization:** The DNS server listens on port 53 for both UDP and TCP connections, handling DNS queries from clients.

#### RedirectingResolver Class  
- **Purpose:** A custom DNS resolver that intercepts DNS queries and redirects them based on predefined rules.
- **Key Methods:** `resolve`, `forward_to_upstream`

---

### Custom Proxy Servers  
The proxy servers further enhance the captive portal by intercepting HTTP requests and providing appropriate responses.

#### Proxy Server for Unauthenticated Users  
- **Purpose:** Redirects HTTP requests from unauthenticated users to the captive portal login page.
- **Implementation:** Uses Python's `http.server` module to create a simple HTTP server.

---

### Features and Functionality  
**Enhanced Captive Portal with DNS and Proxy Redirection**  
Improves user experience by intercepting DNS and HTTP requests, ensuring users are prompted to authenticate.

**Secure Authentication and Authorization**  
Uses hashed passwords and session management tied to IP and MAC addresses.

**Dynamic Network Management**  
Automatically assigns IPv6 addresses and manages devices based on MAC addresses.

**Bandwidth and Usage Enforcement**  
Sets individual bandwidth limits and data caps.

**Real-Time Monitoring and Reporting**  
Provides real-time data on usage and enables administrative oversight.

---

### Results and Testing  
IPv6Spot has been tested extensively to validate its functionality and performance.

- **Functional Testing:** Confirmed the DNS and proxy servers correctly intercept and redirect queries.
- **Performance Testing:** Ensured efficient handling without latency.
- **Security Testing:** Tested against DNS spoofing and unauthorized access.
- **Compatibility Testing:** Verified operation with different client devices.

---

### Conclusion  
IPv6Spot is an innovative solution that brings comprehensive captive portal functionality to IPv6 networks. By integrating custom DNS and proxy servers, the system enhances network access control and user experience.

---

### Future Work  
Potential enhancements to IPv6Spot include:

- **Advanced DNS Features:** DNSSEC validation, support for complex queries.
- **Enhanced Proxy Capabilities:** HTTPS interception.
- **Integration with Security Platforms:** Intrusion detection systems.
- **Scalability Improvements:** Optimize for larger networks.
- **User Interface Enhancements:** Responsive web design.
- **Multi-Language Support:** Localized interfaces.

---

### Acknowledgments  
This project was developed by Abdulkader Alrezej. Special thanks to the developers of Flask, dnslib, SQLite, and Linux networking utilities, which were instrumental in developing this solution.

---

### References  
1. Hagen, Silvia. *IPv6 Essentials.* O'Reilly Media.  
2. *Flask Documentation.* Flask.  
3. *dnslib Documentation.* dnslib.  
4. *SQLite Documentation.* SQLite.  
5. The Linux Foundation. *Linux Advanced Routing & Traffic Control HOWTO.*  
6. Netfilter Project. *nftables.* Netfilter.  
7. Python Documentation. *subprocess Module.*  
8. Python Documentation. *http.server Module.*




---

Appendix: Detailed Code Analysis

To provide a deeper understanding of IPv6Spot, we include an analysis of the key components and functions in the source code related to the custom proxy servers.

Custom Proxy Servers

The proxy servers are designed to intercept HTTP requests and provide appropriate responses to enhance the captive portal functionality.

Proxy Server for Unauthenticated Users

Purpose: Redirects all HTTP GET requests to the captive portal login page for unauthenticated users.

Implementation:

Class Definition: Inherits from http.server.SimpleHTTPRequestHandler.

do_GET Method:

Overrides the default GET request handler.

Sends an HTTP 302 redirect response to the user's browser, pointing to the captive portal login page.


Server Setup:

Uses socketserver.ThreadingTCPServer with socket.AF_INET6 to handle IPv6 connections.

Listens on a specific IPv6 address and port dedicated to unauthenticated user redirection.



Features:

Stateless Handling: Does not maintain any state between requests, ensuring scalability.

Logging: Overrides log_message to suppress unnecessary logging.



Proxy Server for Network Connectivity Checks

Purpose: Provides appropriate HTTP responses to network connectivity checks performed by various operating systems and devices, ensuring they detect the presence of a captive portal.

Implementation:

Class Definition: Inherits from http.server.SimpleHTTPRequestHandler.

do_GET Method:

Parses the requested URL and hostname.

Normalizes the hostname by removing any www. prefix.

Checks the hostname and path against a set of predefined rules corresponding to known network connectivity check URLs.

Provides the expected HTTP responses for each case, such as returning specific text or HTML content.

If the request does not match any known patterns, responds with an HTTP 403 Forbidden status and displays a custom error page.


Helper Functions:

get_network_from_db: Connects to the SQLite database to retrieve the network name, allowing dynamic handling of network-specific requests.



Features:

OS Compatibility: Supports connectivity checks for various operating systems, including Windows (msftconnecttest.com), Apple (captive.apple.com), GNOME (nmcheck.gnome.org), KDE (networkcheck.kde.org), and Android (connectivitycheck.gstatic.com).

Custom Error Pages: Provides informative error pages for blocked requests, including details like server time and client IP.

Dynamic Responses: Adjusts responses based on data retrieved from the database, allowing for flexible network configurations.



Server Setup

Server Initialization:

Uses socketserver.ThreadingTCPServer with socket.AF_INET6 to handle IPv6 connections.

Binds to a specific IPv6 address and port dedicated to handling network connectivity checks and other HTTP requests.


Concurrency:

Employs a threaded server model to handle multiple simultaneous connections efficiently.




---

Conclusion

The addition of custom proxy servers to IPv6Spot significantly enhances its ability to manage network access and improve user experience. By intercepting HTTP requests and providing tailored responses, the system ensures that devices recognize the presence of a captive portal and prompt users to authenticate. This seamless integration of DNS and proxy services with the captive portal functionality sets IPv6Spot apart as a comprehensive solution for IPv6 network management.

Abdulkader Alrezej's work on IPv6Spot demonstrates a deep understanding of networking principles and the challenges associated with IPv6 adoption. The project's open-source nature encourages collaboration and further development, contributing valuable resources to the networking community.



- Main File Directory: /mnt/cerr Copy all files and folders to the directory: /mnt/cerr.

- File tree directory:

		db  >> Database encryption and backup files
		web_dist >> Web Dashboard Pages Files
		console >> Create virtual interfaces for IPv6Spot
		main_sqlite3_database.db >> Main system database Sqlite3
		external_domains >> The addresses of the sites you want to block are stored using the IPv6Spot system.
		dns_server_main.py >> DNS server
		nftable_conf_ipv6 >> nftables rules file
		captive_portal_server.py >> IPv6Spot system
		web_server_main.py >> Back-End of the web control panel
		proxy_server_main.py >> IPv6Spot Web Proxy  A Captive portal detection URLs 
		proxy_server_slave.py >> IPv6Spot Web Proxy  B Respond to detection URLs 
		OpenWRT version used in the system:
		OpenWRT 22.03.0
		Kernel Version	5.10.138

- Operating requirements:

		python --version > Python 3.10.13
		scapy version  2.5.0

	 -

		NAT64 for a IPv6-only network (Jool) >> https://openwrt.org/docs/guide-user/network/ipv6/nat64
  		conntrack
		python3-lzma	3.10.13-2
		python3-multiprocessing	3.10.13-2
		python3-ncurses	3.10.13-2
		python3-openssl	3.10.13-2
		python3-pillow	9.5.0-2
		python3-pip	23.0.1-1
		python3-pkg-resources
		python3-ply	3.11-2
		python3-psutil	5.9.0-2
		python3-pycparser	2.21-2
		python3-pydoc	3.10.13-2
		python3-readline	3.10.13-2
		python3-setuptools	65.5.0-1
		python3-sqlite3	3.10.13-2
		python3-unittest	3.10.13-2
		python3-urllib	3.10.13-2
		python3-uuid	3.10.13-2
		python3-xml python3-xml	3.10.13-2
		python3	3.10.13-2
		python3-asyncio	3.10.13-2
		python3-base	3.10.13-2
		python3-bidict	0.21.2-2
		python3-cffi	1.16.0-1
		python3-cgi	3.10.13-2
		python3-cgitb	3.10.13-2
		python3-codecs	3.10.13-2
		python3-ctypes	3.10.13-2
		python3-dbm	3.10.13-2
		python3-decimal	3.10.13-2
		python3-dev	3.10.13-2
		python3-distutils	3.10.13-2
		python3-email	3.10.13-2
		python3-lib2to3	3.10.13-2
		python3-light	3.10.13-2
		python3-logging	3.10.13-2
		tc-full
		tc-mod-iptables
		sqlite3-cli	3410200-1
		libsqlite3-0	3410200-1
		ip6tables
		nftables
		xtables-nft
		kmod-ip6tables
		ip-full
		iputils-arping
		nmap
		kmod-veth

- pip list
  Package                     Version
------------------------- --------
  	aiodns                    3.2.0
  	aiohttp                   3.9.5
  	aiosignal                 1.3.1
  	altgraph                  0.17.4
  	annotated-types           0.7.0
  	anyio                     4.4.0
  	APScheduler               3.10.4
  	arabic-reshaper           3.0.0
  	async-timeout             4.0.3
  	asyncio                   3.4.3
  	attrs                     23.2.0
  	bcrypt                    4.2.0
  	bidict                    0.21.2
  	blinker                   1.8.2
  	cachelib                  0.13.0
  	cachetools                5.5.0
  	certifi                   2024.7.4
  	cffi                      1.16.0
  	chardet                   5.2.0
  	charset-normalizer        3.3.2
  	click                     8.1.7
  	dnslib                    0.9.25
  	dnspython                 2.6.1
  	exceptiongroup            1.2.2
  	Flask                     3.0.3
  	Flask-KVSession           0.6.2
  	Flask-Session             0.8.0
  	Flask-SQLAlchemy          3.1.1
  	frozenlist                1.4.1
  	greenlet                  3.0.3
  	h11                       0.14.0
  	httpcore                  1.0.5
  	httpx                     0.27.0
  	humanize                  4.10.0
  	idna                      3.7
  	itsdangerous              2.2.0
  	Jinja2                    3.1.4
  	MarkupSafe                2.1.5
  	msgspec                   0.18.6
  	multidict                 6.0.5
  	packaging                 24.1
  	Pillow                    9.5.0
  	pip                       24.2
  	ply                       3.11
  	proxy.py                  2.4.4
  	psutil                    5.9.0
  	pyarmor.cli.core          3.2.9
  	pycares                   4.4.0
  	pycparser                 2.21
  	pycryptodome              3.20.0
  	pydantic                  2.8.2
  	pydantic_core             2.20.1
  	pyinstaller               6.10.0
  	pyinstaller-hooks-contrib 2024.8
  	pyminifier3               2.3.3
  	pyroute2                  0.7.12
  	pytz                      2024.1
  	reportlab                 4.2.2
  	requests                  2.32.3
  	scapy                     2.5.0
  	setuptools                73.0.1
  	simplekv                  0.14.1
  	six                       1.16.0
  	sniffio                   1.3.1
  	SQLAlchemy                2.0.31
  	typing_extensions         4.12.2
  	tzlocal                   5.2
  	urllib3                   2.2.2
  	Werkzeug                  3.0.3
  	wheel                     0.44.0
  	yarl                      1.9.4

- must be disabled Dnsmasq, Also give root permission >> chmod +x *.py

			chmod +x dns_server_main.py
  			chmod +x captive_portal_server.py
  			chmod +x web_server_main.py
  			chmod +x proxy_server_main.py
  			chmod +x proxy_server_slave.py


- Also nftable should be directed to the new nftable rules site at: /etc/init.d/nftables And replace this line " nft -f /etc/nftables.conf " with this line nft -f /mnt/cerr/nftable_conf_ipv6

			nft -f /mnt/cerr/nftable_conf_ipv6
- 
- Run services when OpenWrt boots:

			procd_open_instance
			procd_set_param command /mnt/cerr/proxy_server_main.py
			procd_set_param respawn
			procd_close_instance

			procd_open_instance
			procd_set_param command /mnt/cerr/proxy_server_slave.py
			procd_set_param respawn
			procd_close_instance

			procd_open_instance
			procd_set_param command /mnt/cerr/captive_portal_server.py
			procd_set_param respawn
			procd_close_instance

			procd_open_instance
			procd_set_param command /mnt/cerr/dns_server_main.py
			procd_set_param respawn
			procd_close_instance

			procd_open_instance
			procd_set_param command /mnt/cerr/web_server_main.py
			procd_set_param respawn
			procd_close_instance

**- Please let me know if there is any error during installation or operation to fix it in the previous guide.**

