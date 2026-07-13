#!/usr/bin/env python3
"""
Setup Script for Steganography Detection Toolkit
Automates the complete setup process
"""

import os
import sys
import subprocess
import platform

def run_command(cmd, description):
    """Run a command with error handling"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            print(f"✅ {description} completed successfully")
            return True
        else:
            print(f"❌ {description} failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ {description} failed: {e}")
        return False

def check_python():
    """Check Python version"""
    print("🐍 Checking Python version...")
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("❌ Python 3.7+ required")
        return False
    
    print("✅ Python version compatible")
    return True

def setup_virtual_env():
    """Set up virtual environment"""
    print("\n📦 Setting up virtual environment...")
    
    if os.path.exists("stego-env"):
        print("📁 Virtual environment already exists")
        return True
    
    if not run_command("python -m venv stego-env", "Creating virtual environment"):
        return False
    
    print("✅ Virtual environment created")
    return True

def install_dependencies():
    """Install required packages"""
    print("\n📦 Installing dependencies...")
    
    # Determine activation command
    if platform.system() == "Windows":
        activate_cmd = ".\\stego-env\\Scripts\\Activate"
        pip_cmd = ".\\stego-env\\Scripts\\pip.exe"
    else:
        activate_cmd = "source stego-env/bin/activate"
        pip_cmd = "stego-env/bin/pip"
    
    packages = [
        "stegano",
        "pillow", 
        "numpy",
        "matplotlib",
        "opencv-python-headless"
    ]
    
    for package in packages:
        if not run_command(f"{pip_cmd} install {package}", f"Installing {package}"):
            print(f"⚠️  Failed to install {package}, continuing...")
    
    print("✅ Dependencies installation completed")
    return True

def create_data_directory():
    """Create data directory for user files"""
    print("\n📁 Creating data directory...")
    
    if not os.path.exists("data"):
        os.makedirs("data")
        print("✅ Data directory created")
    else:
        print("📁 Data directory already exists")
    
    # Create README for data directory
    readme_content = """# Data Directory

Put your images and files to analyze in this directory.

## Supported Formats
- Images: JPG, PNG, BMP, TIFF
- Audio: WAV, MP3 (limited)

## Usage
python stego_detector.py detect data/your_image.jpg
python advanced_stego.py data/your_image.jpg
"""
    
    readme_path = os.path.join("data", "README.md")
    if not os.path.exists(readme_path):
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        print("✅ Data README created")
    
    return True

def test_installation():
    """Test the installation"""
    print("\n🧪 Testing installation...")
    
    # Test basic import
    try:
        import stegano
        print("✅ Stegano library imported successfully")
    except ImportError as e:
        print(f"❌ Stegano import failed: {e}")
        return False
    
    # Test PIL
    try:
        from PIL import Image
        print("✅ PIL/Pillow imported successfully")
    except ImportError as e:
        print(f"❌ PIL import failed: {e}")
        return False
    
    # Test with example file if exists
    if os.path.exists("examples/ORIGINAL.jpg"):
        print("\n🔍 Testing with example file...")
        try:
            from PIL import Image
            img = Image.open("examples/ORIGINAL.jpg")
            print(f"✅ Example file loaded: {img.size} {img.mode}")
        except Exception as e:
            print(f"⚠️  Example file test failed: {e}")
    
    return True

def print_usage_instructions():
    """Print usage instructions"""
    print("\n" + "="*60)
    print("🎉 SETUP COMPLETE!")
    print("="*60)
    
    print("\n🚀 Quick Start:")
    print("1. Activate virtual environment:")
    if platform.system() == "Windows":
        print("   .\\stego-env\\Scripts\\Activate")
    else:
        print("   source stego-env/bin/activate")
    
    print("\n2. Run interactive menu:")
    print("   python quick_start.py")
    
    print("\n3. Or use command line:")
    print("   python stego_detector.py detect image.jpg")
    print("   python advanced_stego.py image.jpg")
    
    print("\n4. Put your files in the 'data' directory")
    
    print("\n📚 For detailed instructions, see USAGE_GUIDE.md")
    
    print("\n🐳 For full toolkit with Docker:")
    print("   docker pull dominicbreuker/stego-toolkit")
    print("   docker run -it --rm -v $(pwd)/data:/data dominicbreuker/stego-toolkit /bin/bash")
    
    print("\n" + "="*60)

def main():
    """Main setup function"""
    print("🔍 Steganography Detection Toolkit - Setup")
    print("="*60)
    
    # Check Python
    if not check_python():
        print("\n❌ Setup failed due to Python version incompatibility")
        return False
    
    # Set up virtual environment
    if not setup_virtual_env():
        print("\n❌ Setup failed during virtual environment creation")
        return False
    
    # Install dependencies
    if not install_dependencies():
        print("\n⚠️  Some dependencies failed to install, but continuing...")
    
    # Create directories
    create_data_directory()
    
    # Test installation
    test_installation()
    
    # Print usage instructions
    print_usage_instructions()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n✅ Setup completed successfully!")
        else:
            print("\n❌ Setup encountered errors")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        sys.exit(1)
