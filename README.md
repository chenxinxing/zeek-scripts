# Zeek Scripts Repository

A collection of Zeek (formerly Bro) network security monitoring scripts for various protocols and use cases.

## Features

- Custom Zeek scripts for network traffic analysis
- Protocol-specific detection and logging
- Extensible framework for security monitoring
- Ready-to-use scripts for common network security tasks

## Getting Started

### Prerequisites

- Zeek network security monitor installed ([installation guide](https://docs.zeek.org/en/master/install/install.html))
- Basic understanding of Zeek scripting

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/chenxinxing/zeek-scripts.git
   ```
2. Copy scripts to your Zeek scripts directory:
   ```bash
   cp -r zeek-scripts/ /usr/local/zeek/share/zeek/site/
   ```
3. Load scripts in your `local.zeek` file:
   ```zeek
   @load ./zeek-scripts
   ```

## Usage

Run Zeek with your desired scripts:
```bash
zeek -i <interface> zeek-scripts/<script-name>
```

## Script Categories

- **Protocol Analysis**: Scripts for specific protocols (HTTP, DNS, SSL, etc.)
- **Security Detection**: Scripts for detecting suspicious activities
- **Logging Enhancements**: Extended logging capabilities
- **Performance Tools**: Scripts for monitoring and optimizing Zeek performance

## Contributing

We welcome contributions! Please follow these guidelines:
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the BSD License - see the [LICENSE](LICENSE) file for details.

## Resources

- [Zeek Documentation](https://docs.zeek.org)
- [Zeek Scripting Reference](https://docs.zeek.org/en/master/script-reference/index.html)
- [Zeek Community](https://zeek.org/community/)