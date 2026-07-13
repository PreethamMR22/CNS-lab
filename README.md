# 🔍 Steganography Detection Toolkit

A comprehensive steganography detection and analysis toolkit designed for CTF challenges, digital forensics, and security research.

## 🎯 What It Does

- **Detects hidden data** in images and audio files
- **Extracts concealed messages** using multiple techniques  
- **Performs statistical analysis** to identify steganography
- **Supports various file formats** (JPEG, PNG, BMP, WAV, MP3)
- **Provides both basic and advanced detection methods**

## 🚀 Quick Start

### Option 1: Automatic Setup (Recommended)

```bash
python setup.py
```

This will:
- Create virtual environment
- Install all dependencies
- Set up directories
- Test the installation

### Option 2: Manual Setup

```bash
# Create virtual environment
python -m venv stego-env

# Activate (Windows)
.\stego-env\Scripts\Activate

# Install dependencies
pip install stegano pillow numpy matplotlib opencv-python-headless

# Run interactive menu
python quick_start.py
```

## 🛠️ Usage

### Interactive Menu (Easiest)

```bash
python quick_start.py
```

Provides a user-friendly menu for all operations.

### Command Line

**Basic Detection:**
```bash
python stego_detector.py detect image.jpg
```

**Advanced Analysis:**
```bash
python advanced_stego.py image.jpg
```

**Hide Message:**
```bash
python stego_detector.py hide image.jpg --message "Secret text" --output stego.jpg
```

**Extract Message:**
```bash
python stego_detector.py extract stego.jpg
```

## 🔬 Detection Methods

### Statistical Analysis
- **File Entropy**: Detects encrypted/hidden data
- **Chi-Square Test**: Identifies LSB steganography  
- **RS Analysis**: Regular/Singleton group detection
- **Histogram Analysis**: Pattern irregularities

### Technical Analysis
- **LSB Extraction**: Least Significant Bit detection
- **Metadata Analysis**: EXIF and hidden metadata
- **Color Diversity**: Statistical anomaly detection
- **Pattern Recognition**: Unusual pixel patterns

## 📁 File Structure

```
stego-toolkit/
├── setup.py                 # Automatic setup script
├── quick_start.py           # Interactive menu
├── stego_detector.py        # Basic detection & LSB
├── advanced_stego.py        # Advanced statistical analysis
├── USAGE_GUIDE.md           # Comprehensive documentation
├── stego-env/               # Python virtual environment
├── data/                    # Your files for analysis
├── examples/                # Test files and examples
└── scripts/                 # Additional analysis scripts
```

## 🐳 Docker Option (Full Toolkit)

For access to 50+ professional steganography tools:

```bash
# Pull pre-built image
docker pull dominicbreuker/stego-toolkit

# Run with your files
docker run -it --rm -v $(pwd)/data:/data dominicbreuker/stego-toolkit /bin/bash

# Inside container:
check_jpg.sh image.jpg
brute_jpg.sh image.jpg wordlist.txt
```

**Docker Tools Include:**
- Stegdetect, Stegbreak, Steghide
- Zsteg, Stegoveritas  
- Binwalk, Foremost, Exiftool
- GUI: Stegsolve, Steganabara, SonicVisualiser

## 🎨 Example Results

**Normal Image:**
```
=== File Entropy Analysis ===
Entropy: 7.9629
✅ Normal entropy range

=== Chi-Square LSB Test ===
Average chi-square: 4499.29
⚠️  High chi-square - possible LSB steganography
```

**Steganography Detected:**
```
=== File Entropy Analysis ===
Entropy: 7.9371
⚠️  High entropy - possible encrypted/hidden data

=== LSB Analysis ===
✅ LSB message found: "Secret test message"
```

## 🔧 Supported Formats

### Images
- **JPEG/JPG**: Most common steganography target
- **PNG**: Lossless, excellent for LSB
- **BMP**: Uncompressed, easy to analyze
- **TIFF**: Multiple compression types

### Audio
- **WAV**: Uncompressed audio
- **MP3**: Limited steganography support

## 🚨 Detection Indicators

### ⚠️ Warning Signs
- **High entropy (>7.5)**: Encrypted/hidden data likely
- **High chi-square (>3.84)**: LSB steganography detected
- **Low color diversity**: Suspicious patterns
- **Irregular histograms**: Manipulation evidence
- **Large metadata**: Hidden information

### ✅ Normal Indicators  
- **Normal entropy (6.0-7.5)**: Regular image data
- **Low chi-square (<3.84)**: No LSB steganography
- **Normal diversity**: Typical characteristics

## 📚 Applications

### CTF Challenges
- HackTheBox steganography challenges
- CTFtime forensic challenges
- Capture the Flag competitions

### Digital Forensics
- Hidden data recovery
- Evidence extraction
- File analysis

### Security Research
- Steganography detection research
- Tool evaluation
- Method development

### Educational
- Learning steganography concepts
- Understanding detection techniques
- Practical demonstrations

## 🛡️ Limitations

### Detection Limits
- **Compression**: Can destroy hidden data
- **Encryption**: Makes detection harder
- **Advanced methods**: May evade simple tests
- **File size**: Large files slower to analyze

### False Positives
- **Statistical tests**: Can be misleading
- **Natural patterns**: May trigger alerts
- **Compression artifacts**: Look like steganography

## 🔧 Troubleshooting

### Virtual Environment Issues
```bash
# Recreate environment
python -m venv stego-env
.\stego-env\Scripts\Activate
pip install stegano pillow numpy matplotlib opencv-python-headless
```

### Docker Issues
```bash
# Check Docker
docker info

# Rebuild if needed
docker build -t local/stego:latest .
```

### Import Errors
```bash
# Install missing packages
pip install <package_name>
```

## 📖 Documentation

- **USAGE_GUIDE.md**: Comprehensive usage instructions
- **quick_start.py**: Interactive menu system
- **setup.py**: Automated installation

## 🤝 Contributing

This toolkit is designed for:
- Educational purposes
- CTF challenges  
- Security research
- Digital forensics

## ⚖️ Legal Notice

This toolkit is intended for:
- Educational and research purposes
- Authorized security testing
- Digital forensics investigations

Users are responsible for ensuring compliance with applicable laws and regulations.

## 📞 Support

For issues and questions:
1. Check USAGE_GUIDE.md first
2. Verify environment setup  
3. Test with example files
4. Use appropriate tools for file types

---

**Remember**: Steganography detection is about finding anomalies. What looks "wrong" or "unusual" is often where hidden data lies! 🔍
