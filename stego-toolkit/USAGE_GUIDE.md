# Steganography Detection Toolkit - Usage Guide

## 🎯 Overview

This toolkit provides comprehensive steganography detection and analysis capabilities. It includes both Python-based tools and Docker container support for advanced forensic analysis.

## 🚀 Quick Start

### Option 1: Python Virtual Environment (Recommended for Windows)

```bash
# Activate the virtual environment
.\stego-env\Scripts\Activate

# Basic steganography detection
python stego_detector.py detect image.jpg

# Advanced analysis
python advanced_stego.py image.jpg

# Hide a message
python stego_detector.py hide image.jpg --message "Secret message" --output stego_image.jpg
```

### Option 2: Docker Container (Full Toolkit)

```bash
# Start the container
docker run -it --rm -v $(pwd)/data:/data dominicbreuker/stego-toolkit /bin/bash

# Use screening scripts
check_jpg.sh image.jpg
check_png.sh image.png
```

## 📁 File Structure

```
stego-toolkit/
├── stego_detector.py          # Basic detection and LSB steganography
├── advanced_stego.py          # Advanced statistical analysis
├── stego-env/                 # Python virtual environment
├── examples/                  # Test images and files
│   ├── ORIGINAL.jpg
│   ├── ORIGINAL.png
│   ├── ORIGINAL.mp3
│   ├── ORIGINAL.wav
│   └── secret_message.txt
├── data/                      # Your files for analysis
├── scripts/                   # Additional analysis scripts
└── bin/                       # Docker build scripts
```

## 🔧 Tools and Features

### 1. Basic Steganography Detection (`stego_detector.py`)

**Commands:**
```bash
# Detect steganography
python stego_detector.py detect image.jpg

# Hide message using LSB
python stego_detector.py hide image.jpg --message "Your secret" --output output.jpg

# Extract LSB messages
python stego_detector.py extract image.jpg
```

**Features:**
- Image metadata analysis
- LSB (Least Significant Bit) detection
- Statistical analysis
- Color diversity analysis
- LSB visualization output

### 2. Advanced Detection (`advanced_stego.py`)

**Commands:**
```bash
# Full comprehensive analysis
python advanced_stego.py image.jpg

# Entropy analysis only
python advanced_stego.py image.jpg --entropy-only

# LSB-focused analysis
python advanced_stego.py image.jpg --lsb-only
```

**Detection Methods:**
- **File Entropy Analysis**: Detects encrypted/hidden data through entropy calculation
- **Chi-Square Test**: Statistical test for LSB steganography
- **RS Analysis**: Regular/Singleton group analysis
- **Histogram Analysis**: Detects irregular patterns in color channels
- **Metadata Extraction**: Analyzes EXIF and other metadata
- **Message Extraction**: Attempts to extract hidden messages

## 🎨 Detection Indicators

The tools will alert you to potential steganography with these indicators:

### ⚠️ Warning Signs
- **High entropy (>7.5)**: Possible encrypted/hidden data
- **High chi-square (>3.84)**: LSB steganography likely
- **Low color diversity**: Suspicious patterns
- **Irregular histogram patterns**: Possible manipulation
- **Large metadata fields**: Hidden data in metadata

### ✅ Normal Indicators
- **Normal entropy (6.0-7.5)**: Regular image data
- **Low chi-square (<3.84)**: No LSB steganography detected
- **Normal color diversity**: Typical image characteristics

## 📊 Example Usage

### Analyzing an Image

```bash
# Basic analysis
python stego_detector.py detect examples/ORIGINAL.jpg

# Advanced analysis
python advanced_stego.py examples/ORIGINAL.jpg
```

**Sample Output:**
```
============================================================
COMPREHENSIVE STEGANOGRAPHY ANALYSIS
File: examples/ORIGINAL.jpg
============================================================

=== File Entropy Analysis ===
File size: 253,282 bytes
Entropy: 7.9629
⚠️  High entropy - possible encrypted/hidden data

=== Chi-Square LSB Test ===
Average chi-square value: 4499.2905
⚠️  High chi-square - possible LSB steganography
```

### Creating Steganography

```bash
# Hide a message
python stego_detector.py hide examples/ORIGINAL.jpg --message "This is secret!" --output secret.jpg

# Verify the hidden message
python advanced_stego.py secret.jpg --lsb-only
```

## 🐳 Docker Advanced Usage

For the full toolkit with 50+ steganography tools:

```bash
# Pull the pre-built image
docker pull dominicbreuker/stego-toolkit

# Run with your files
docker run -it --rm -v $(pwd)/data:/data dominicbreuker/stego-toolkit /bin/bash

# Inside container:
# Quick JPG analysis
check_jpg.sh image.jpg

# Brute force extraction with wordlist
brute_jpg.sh image.jpg wordlist.txt

# PNG analysis
check_png.sh image.png
```

### Docker GUI Tools

```bash
# Start VNC for GUI tools
start_vnc.sh
# Connect to http://localhost:6901/?password=<password>

# Or SSH with X11 forwarding
start_ssh.sh
# ssh -X root@localhost
```

## 🔍 Analysis Techniques Explained

### 1. LSB (Least Significant Bit) Steganography
- **How it works**: Hidden data is encoded in the least significant bits of pixel values
- **Detection**: Chi-square test, RS analysis, LSB extraction
- **Tools**: `stegano` library, custom LSB analysis

### 2. Statistical Analysis
- **Entropy**: Measures randomness in the data
- **Chi-square**: Tests for even/odd pixel distribution
- **RS analysis**: Detects patterns in pixel groups

### 3. Metadata Steganography
- **EXIF data**: Hidden information in image metadata
- **Comment fields**: Large text fields in metadata
- **Detection**: Metadata extraction and analysis

## 🛠️ Supported File Formats

### Images
- **JPEG/JPG**: Most common for steganography
- **PNG**: Lossless, good for LSB
- **BMP**: Uncompressed, easy to analyze
- **TIFF**: Multiple compression types

### Audio
- **WAV**: Uncompressed audio
- **MP3**: Compressed audio (limited steganography)

## 📝 Best Practices

### For Detection
1. **Start with basic analysis** before advanced tools
2. **Compare with originals** when possible
3. **Use multiple detection methods** for accuracy
4. **Check file entropy** as a quick indicator
5. **Analyze metadata** for hidden information

### For Steganography
1. **Use appropriate formats** (PNG for LSB, JPEG for other methods)
2. **Consider compression effects** on hidden data
3. **Test extraction** before distribution
4. **Use strong passwords** for encrypted steganography

## 🚨 Limitations

### Detection Limitations
- **Compression**: Can destroy hidden data
- **Encryption**: Makes detection harder
- **Advanced methods**: May evade simple tests
- **File size limits**: Large files harder to analyze

### Tool Limitations
- **False positives**: Statistical tests can be misleading
- **Format support**: Not all formats supported
- **Performance**: Large files may be slow to analyze

## 🔧 Troubleshooting

### Common Issues

**Virtual Environment Issues:**
```bash
# Recreate environment
python -m venv stego-env
.\stego-env\Scripts\Activate
pip install stegano pillow numpy matplotlib opencv-python-headless
```

**Docker Issues:**
```bash
# Check Docker status
docker info

# Rebuild if needed
docker build -t local/stego:latest .
```

**Import Errors:**
```bash
# Install missing packages
pip install <package_name>
```

## 📚 Further Learning

### Steganography Techniques
- **LSB**: Most basic and common
- **DCT**: Discrete Cosine Transform
- **Frequency Domain**: Audio steganography
- **Metadata**: EXIF and comment fields

### Advanced Tools
- **Stegsolve**: Image analysis tool
- **Zsteg**: Ruby-based LSB detection
- **Steghide**: Command-line steganography
- **Outguess**: JPEG steganography

## 🎯 CTF and Forensic Applications

This toolkit is designed for:
- **CTF challenges**: HackTheBox, CTFtime
- **Digital forensics**: Hidden data recovery
- **Security analysis**: Steganography detection
- **Educational purposes**: Learning steganography

## 📞 Support

For issues and questions:
1. Check this guide first
2. Verify environment setup
3. Test with example files
4. Use appropriate tools for your file type

---

**Remember**: Steganography detection is often about finding anomalies. What looks "wrong" or "unusual" is often where hidden data lies!


how to run ? 
# Step 1 — Navigate to the project
cd C:\Users\preet\OneDrive\Desktop\Stag\stego-toolkitSS

# Step 2 — Activate the virtual environment
.\stego-env\Scripts\Activate

# Step 3 — Run the Flask web app
python app.py
