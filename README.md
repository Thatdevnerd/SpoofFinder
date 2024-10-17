# 🚨 SpoofFinder 🚨

**SpoofFinder** is a tool designed to check whether a target ASN (Autonomous System Number) supports IP header modification, commonly referred to as IP spoofing. The tool fetches and analyzes data from multiple sources, providing a comprehensive report on the spoofing status of a given ASN, IP address, or CIDR range.

## ⚡️ Features

- 🛡️ **ASN Spoofing Check**: Determines whether an ASN allows IP header modification (IPHM), indicating whether the ASN supports spoofed packet routing.
- 📊 **Detailed ASN Information**: Retrieves detailed information about an ASN, including country, number of routed IPs, and last spoofing check.
- 📧 **Email and Phone Parsing**: Extracts contact details (email, phone) from public ASN databases.
- 🔍 **Related Links Search**: Performs search engine queries for related server information based on the ASN.
- 🌈 **Rich CLI Output**: Utilizes `rich` for visually appealing, colorful logs and outputs.

## 🚀 Quick Run

Follow these steps to quickly set up and run SpoofFinder:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/MatrixTM/SpoofFinder.git
   cd spoof-finder
   ```

2. **Install dependencies**:
   Ensure you have Python 3.7+ installed. Then, run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool**:
   You can check the spoofing status of an ASN, IP, or CIDR range using the following command:
   ```bash
   python spoof_finder.py -t AS15169
   ```

4. **Interactive Mode**:
   If you don't pass any arguments, SpoofFinder will prompt you to input a target interactively:
   ```bash
   python spoof_finder.py
   ```

## 🛠️ Requirements

SpoofFinder depends on the following Python libraries:

```bash
pip install httpx netaddr rich argon2-cffi aioconsole
```

## 🖥️ Usage

SpoofFinder can be run from the command line, passing the target ASN, IP address, or CIDR range as an argument.

### Example

To check if ASN 15169 (Google) supports IP header modification:

```bash
python spoof_finder.py -t AS15169
```

You can also use an IP address or CIDR range to find the corresponding ASN and check its spoofing status:

```bash
python spoof_finder.py -t 8.8.8.8
```

### Input Types

- **ASN**: Autonomous System Number (e.g., `AS15169` or just `15169`).
- **IP Address**: Will resolve the IP to its corresponding ASN and check the spoofing status.
- **CIDR Range**: Supports input of IP ranges in CIDR format (e.g., `8.8.8.0/24`).

## 📄 Output Example

Here is an example of the tool's output:

```plaintext
Getting information for ASN: 15169...
ASN Name: GOOGLE
Supports IP Header Modification (IPHM): No
Last Checked: Sep 15 2023 04:35PM
Country: US (USA)
Number of Routed IPs: 26,214,400
Contact Email: abuse@google.com
Contact Phone: +1 650-253-0000
Related Links:
- https://example.com/link1
- https://example.com/link2
```

## 📁 File Structure

- `spoof_finder.py`: The main script that handles checking ASN spoofing status and gathering additional information.
- `README.md`: This file, providing project documentation.

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Feel free to open issues or submit pull requests. Please follow the repository's guidelines for code style and contributions.

## 🚧 Future Enhancements

- ⚙️ Add more data sources to check spoofing capabilities.
- 🗂️ Implement caching to reduce API call overhead for repeated queries.
- 🔧 Improved error handling and log management.
