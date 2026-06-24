# Prodigy_CS_T5
NetworkPacketAnalyzer
# Packet Pulse - Network Packet Analyzer

A Flask-based network packet analyzer that captures and displays network traffic in real time using Scapy. The application monitors packets flowing through your machine's network interface and presents key information such as source IP, destination IP, protocol type, packet length, ports, and payload previews through an interactive web dashboard.

## 📌 Project Information

**Repository Name:** Prodigy_CS_T5

**GitHub Profile:**
https://github.com/shivamshuklabtech

## 🚀 Features

* Real-time packet capture
* Live traffic monitoring dashboard
* Displays source and destination IP addresses
* Detects common protocols:

  * TCP
  * UDP
  * ICMP
* Packet length analysis
* Source and destination port identification
* Payload preview extraction
* Start/Stop packet capture controls
* Interactive web-based interface
* Built using Flask and Scapy

## 🔐 Ethical Use Notice

This project is intended strictly for educational and authorized network analysis purposes.

### Authorized Usage

✅ Monitor your own device traffic

✅ Analyze networks you own

✅ Capture packets on systems where you have explicit permission

### Unauthorized Usage

❌ Monitoring third-party networks

❌ Capturing traffic without consent

❌ Unauthorized surveillance

❌ Illegal network monitoring activities

Always comply with local laws and organizational policies before capturing network traffic.

## 🛠️ Technologies Used

* Python 3
* Flask
* Scapy
* HTML5
* CSS3
* JavaScript
* REST API
* Threading

## 📂 Project Structure

```text
Prodigy_CS_T5/
│
├── app.py
├── requirements.txt
└── README.md
```

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/shivamshuklabtech/Prodigy_CS_T5.git
cd Prodigy_CS_T5
```

### 2. Create a Virtual Environment (Optional)

```bash
python -m venv venv
```

Activate the environment:

#### Windows

```bash
venv\Scripts\activate
```

#### Linux/macOS

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install flask scapy
```

or

```bash
pip install -r requirements.txt
```

## ▶️ Running the Application

Packet sniffing requires elevated privileges.

### Linux

```bash
sudo python app.py
```

### Windows (Run Terminal as Administrator)

```bash
python app.py
```

Open your browser and navigate to:

```text
http://127.0.0.1:5000
```

## 📸 How to Use

1. Start the Flask application.
2. Open the web dashboard.
3. Click **Start Capture**.
4. Generate network activity by:

   * Browsing websites
   * Pinging hosts
   * Downloading files
5. Observe captured packets in real time.
6. Click **Stop Capture** to stop monitoring.

## 📊 Packet Information Displayed

For every captured packet, the application displays:

| Field          | Description                  |
| -------------- | ---------------------------- |
| Time           | Capture timestamp            |
| Source IP      | Sender address               |
| Destination IP | Receiver address             |
| Protocol       | TCP, UDP, ICMP, or OTHER     |
| Ports          | Source and destination ports |
| Length         | Packet size in bytes         |
| Payload        | Preview of packet contents   |

## 🌐 API Endpoints

### Start Packet Capture

**POST**

```http
/api/start
```

#### Response

```json
{
  "running": true
}
```

---

### Stop Packet Capture

**POST**

```http
/api/stop
```

#### Response

```json
{
  "running": false
}
```

---

### View Captured Packets

**GET**

```http
/api/packets
```

#### Response

```json
{
  "running": true,
  "count": 25,
  "packets": [
    {
      "src": "192.168.1.5",
      "dst": "8.8.8.8",
      "proto": "UDP",
      "length": 64
    }
  ]
}
```

## 🔍 Supported Protocols

### TCP (Transmission Control Protocol)

Used for:

* HTTP/HTTPS
* FTP
* SSH
* Email services

### UDP (User Datagram Protocol)

Used for:

* DNS
* Streaming services
* VoIP applications

### ICMP (Internet Control Message Protocol)

Used for:

* Ping requests
* Network diagnostics
* Error reporting

## 🎯 Learning Objectives

This project demonstrates:

* Network packet analysis
* Packet sniffing with Scapy
* Protocol identification
* Network traffic monitoring
* Flask web development
* Thread management
* Real-time data visualization
* Client-server communication

## ⚠️ Requirements

* Python 3.8+
* Administrator/Sudo privileges
* Active network connection
* Scapy installed correctly
  
## 🤝 Contributing

Contributions and improvements are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Shivam Shukla**

GitHub: https://github.com/shivamshuklabtech

---

⭐ If you found this project useful, consider giving it a star on GitHub.

