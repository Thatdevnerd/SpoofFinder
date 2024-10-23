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
pip install httpx netaddr rich aioconsole git+https://github.com/soxoj/async-search-scraper
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
[21:23:25] 🔍 Fetching data for ASN: AS15169...                                
[21:23:28] 🌍 ASN Name: GOOGLE                                                 
           🔢 ASN Number: AS15169                                              
           🌐 Site: google.com                                                 
           🏆 ASN Rank: 1790                                                   
           🛡️ Spoofable: No                                                     
           🌍 Country: USA                                                     
           🌐 Client IPv4: 35.194.140.0/24                                     
           ⏱️ Last Checked: Dec 21 2017 08:40 AM                                
           📧 Contact Email: network-abuse@google.com                          
           📞 Contact Phone: +1-650-253-0000                                   
[21:23:55] 🔗 Related Links:                                                   
           - https://cloud.google.com/                                         
           - https://console.cloud.google.com/                                 
           - https://cloud.google.com/gcp/                                     
           - https://cloud.google.com/compute/                                 
           - https://www.google.com/about/datacenters/                         
           - https://cloud.google.com/products/calculator                      
           - https://cloud.google.com/hosting-options/                         
           - https://www.google.com/about/datacenters/efficiency/              
           - https://www.google.com/about/datacenters/locations/               
           - https://en.wikipedia.org/wiki/Google_data_centers                 
           - https://cloud.google.com/serverless/                              
           - https://cloud.google.com/compute/vm-instance-pricing              
           - https://www.google.com/about/datacenters/gallery/                 
           - https://blog.google/products/google-cloud/introducing-google-cloud/ 
           - https://www.google.com/                                           
           - https://support.google.com/?hl=en                                 
           - https://accounts.google.com/                                      
           - https://about.google/intl/ALL_us/                                 
           - https://www.google.com/advanced_search                            
           - https://maps.google.com/                                          
           - https://en.wikipedia.org/wiki/Google                              
           - https://www.google.de/                                            
           - https://www.google.es/                                            
           - https://www.google.com.br/                                        
           - https://www.google.ie/intl/en/                                    
           - https://www.google.com.mx/                                        
           - https://www.google.dk/index.html                                  
           - https://www.google.com.tw/
```

## 📝 About Data Sources
SpoofFinder gathers ASN and IP spoofing data from multiple sources, including:

- [caida.org](https://caida.org): For information on ASN spoofing status.
- [arin.net](https://arin.net): For obtaining contact information (email, phone) associated with ASNs.
- [ipapi.co](https://ipapi.co): For IP geolocation and ASN details based on the target IP.


## 📁 File Structure

- `spoof_finder.py`: The main script that handles checking ASN spoofing status and gathering additional information.
- `README.md`: This file, providing project documentation.
- `requirements.txt`: A list of Python libraries and their versions required to run the tool.
- `LICENSE`: The license information for the project.

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Feel free to open issues or submit pull requests. Please follow the repository's guidelines for code style and contributions.

## 🚧 Future Enhancements

- ⚙️ Add more data sources to check spoofing capabilities.
- 🗂️ Implement caching to reduce API call overhead for repeated queries.
- 🔧 Improved error handling and log management.
