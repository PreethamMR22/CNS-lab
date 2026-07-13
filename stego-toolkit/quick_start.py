#!/usr/bin/env python3
"""
Quick Start Script for Steganography Detection Toolkit
Interactive menu for easy access to all tools
"""

import os
import sys
import subprocess
import platform

def clear_screen():
    """Clear the terminal screen"""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def check_virtual_env():
    """Check if virtual environment is activated"""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

def activate_virtual_env():
    """Instructions for activating virtual environment"""
    print("⚠️  Virtual environment not activated!")
    print("\nTo activate the virtual environment, run:")
    print("   .\\stego-env\\Scripts\\Activate")
    print("\nThen run this script again.")
    input("\nPress Enter to exit...")
    sys.exit(1)

def run_command(cmd):
    """Run a command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1

def menu():
    """Main menu interface"""
    while True:
        clear_screen()
        print("=" * 60)
        print("🔍 STEGANOGRAPHY DETECTION TOOLKIT")
        print("=" * 60)
        print("\n📁 Current directory:", os.getcwd())
        print("\n🎯 Choose an option:")
        print("\n1. 🔍 Basic Image Analysis")
        print("2. 🔬 Advanced Steganography Detection")
        print("3. 📝 Hide Message in Image")
        print("4. 🔓 Extract Hidden Message")
        print("5. 📊 File Entropy Analysis")
        print("6. 🎨 Analyze All Images in Directory")
        print("7. 🐳 Docker Container Info")
        print("8. 📚 View Usage Guide")
        print("9. 🧪 Test with Example Files")
        print("0. 🚪 Exit")
        
        choice = input("\nEnter your choice (0-9): ").strip()
        
        if choice == '1':
            basic_analysis()
        elif choice == '2':
            advanced_analysis()
        elif choice == '3':
            hide_message()
        elif choice == '4':
            extract_message()
        elif choice == '5':
            entropy_analysis()
        elif choice == '6':
            analyze_directory()
        elif choice == '7':
            docker_info()
        elif choice == '8':
            view_guide()
        elif choice == '9':
            test_examples()
        elif choice == '0':
            print("\n👋 Goodbye!")
            break
        else:
            print("\n❌ Invalid choice. Please try again.")
            input("Press Enter to continue...")

def basic_analysis():
    """Basic steganography analysis"""
    clear_screen()
    print("🔍 Basic Image Analysis")
    print("-" * 30)
    
    image_path = input("Enter image path (or drag and drop): ").strip().strip('"')
    
    if not os.path.exists(image_path):
        print(f"\n❌ File not found: {image_path}")
        input("Press Enter to continue...")
        return
    
    print(f"\n🔍 Analyzing: {image_path}")
    print("Running basic steganography detection...")
    
    stdout, stderr, returncode = run_command(f"python stego_detector.py detect \"{image_path}\"")
    
    if returncode == 0:
        print("\n✅ Analysis Complete:")
        print(stdout)
    else:
        print(f"\n❌ Error: {stderr}")
    
    input("\nPress Enter to continue...")

def advanced_analysis():
    """Advanced steganography detection"""
    clear_screen()
    print("🔬 Advanced Steganography Detection")
    print("-" * 40)
    
    image_path = input("Enter image path (or drag and drop): ").strip().strip('"')
    
    if not os.path.exists(image_path):
        print(f"\n❌ File not found: {image_path}")
        input("Press Enter to continue...")
        return
    
    print(f"\n🔬 Running comprehensive analysis on: {image_path}")
    print("This may take a moment...")
    
    stdout, stderr, returncode = run_command(f"python advanced_stego.py \"{image_path}\"")
    
    if returncode == 0:
        print("\n✅ Advanced Analysis Complete:")
        print(stdout)
    else:
        print(f"\n❌ Error: {stderr}")
    
    input("\nPress Enter to continue...")

def hide_message():
    """Hide a message in an image"""
    clear_screen()
    print("📝 Hide Message in Image")
    print("-" * 30)
    
    image_path = input("Enter source image path: ").strip().strip('"')
    if not os.path.exists(image_path):
        print(f"\n❌ File not found: {image_path}")
        input("Press Enter to continue...")
        return
    
    message = input("Enter secret message: ").strip()
    if not message:
        print("\n❌ Message cannot be empty")
        input("Press Enter to continue...")
        return
    
    output_path = input("Enter output image path: ").strip().strip('"')
    if not output_path:
        output_path = f"stego_{os.path.basename(image_path)}"
    
    print(f"\n📝 Hiding message in: {image_path}")
    print(f"📁 Output will be: {output_path}")
    
    stdout, stderr, returncode = run_command(f'python stego_detector.py hide "{image_path}" --message "{message}" --output "{output_path}"')
    
    if returncode == 0:
        print("\n✅ Message hidden successfully!")
        print(stdout)
        print(f"\n🔍 You can now analyze the output with: python advanced_stego.py \"{output_path}\"")
    else:
        print(f"\n❌ Error: {stderr}")
    
    input("\nPress Enter to continue...")

def extract_message():
    """Extract hidden message"""
    clear_screen()
    print("🔓 Extract Hidden Message")
    print("-" * 30)
    
    image_path = input("Enter steganography image path: ").strip().strip('"')
    
    if not os.path.exists(image_path):
        print(f"\n❌ File not found: {image_path}")
        input("Press Enter to continue...")
        return
    
    print(f"\n🔓 Extracting messages from: {image_path}")
    
    stdout, stderr, returncode = run_command(f"python stego_detector.py extract \"{image_path}\"")
    
    if returncode == 0:
        print("\n✅ Extraction Complete:")
        print(stdout)
    else:
        print(f"\n❌ Error: {stderr}")
    
    input("\nPress Enter to continue...")

def entropy_analysis():
    """File entropy analysis"""
    clear_screen()
    print("📊 File Entropy Analysis")
    print("-" * 30)
    
    file_path = input("Enter file path: ").strip().strip('"')
    
    if not os.path.exists(file_path):
        print(f"\n❌ File not found: {file_path}")
        input("Press Enter to continue...")
        return
    
    print(f"\n📊 Analyzing entropy of: {file_path}")
    
    stdout, stderr, returncode = run_command(f"python advanced_stego.py \"{file_path}\" --entropy-only")
    
    if returncode == 0:
        print("\n✅ Entropy Analysis Complete:")
        print(stdout)
    else:
        print(f"\n❌ Error: {stderr}")
    
    input("\nPress Enter to continue...")

def analyze_directory():
    """Analyze all images in directory"""
    clear_screen()
    print("🎨 Analyze All Images in Directory")
    print("-" * 40)
    
    dir_path = input("Enter directory path: ").strip().strip('"')
    
    if not os.path.exists(dir_path):
        print(f"\n❌ Directory not found: {dir_path}")
        input("Press Enter to continue...")
        return
    
    # Find image files
    image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif'}
    image_files = []
    
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if os.path.splitext(file.lower())[1] in image_extensions:
                image_files.append(os.path.join(root, file))
    
    if not image_files:
        print(f"\n❌ No image files found in: {dir_path}")
        input("Press Enter to continue...")
        return
    
    print(f"\n🎨 Found {len(image_files)} image files")
    print("Running quick analysis on each file...")
    
    for image_file in image_files:
        print(f"\n🔍 Analyzing: {os.path.basename(image_file)}")
        stdout, stderr, returncode = run_command(f"python advanced_stego.py \"{image_file}\" --entropy-only")
        if returncode == 0:
            print(stdout[:200] + "..." if len(stdout) > 200 else stdout)
    
    input("\nPress Enter to continue...")

def docker_info():
    """Docker information"""
    clear_screen()
    print("🐳 Docker Container Information")
    print("-" * 40)
    
    print("\n📦 Docker Commands for Full Toolkit:")
    print("\n1. Pull pre-built image:")
    print("   docker pull dominicbreuker/stego-toolkit")
    
    print("\n2. Run with your files:")
    print("   docker run -it --rm -v $(pwd)/data:/data dominicbreuker/stego-toolkit /bin/bash")
    
    print("\n3. Inside container:")
    print("   check_jpg.sh image.jpg")
    print("   check_png.sh image.png")
    print("   brute_jpg.sh image.jpg wordlist.txt")
    
    print("\n4. GUI tools:")
    print("   start_vnc.sh  # Browser-based")
    print("   start_ssh.sh  # SSH with X11 forwarding")
    
    print("\n🔧 Available Tools in Docker:")
    print("- Stegdetect, Stegbreak, Steghide")
    print("- Zsteg, Stegoveritas")
    print("- Binwalk, Foremost, Exiftool")
    print("- GUI: Stegsolve, Steganabara, SonicVisualiser")
    
    stdout, stderr, returncode = run_command("docker --version")
    if returncode == 0:
        print(f"\n✅ Docker Status: {stdout.strip()}")
    else:
        print("\n❌ Docker not installed or not running")
    
    input("\nPress Enter to continue...")

def view_guide():
    """View usage guide"""
    clear_screen()
    print("📚 Usage Guide")
    print("-" * 20)
    
    if os.path.exists("USAGE_GUIDE.md"):
        print("📖 Opening USAGE_GUIDE.md...")
        try:
            with open("USAGE_GUIDE.md", 'r', encoding='utf-8') as f:
                content = f.read()
                print(content[:1000] + "\n... (truncated for display)")
        except Exception as e:
            print(f"❌ Error reading guide: {e}")
    else:
        print("❌ USAGE_GUIDE.md not found")
    
    print("\n📚 For complete documentation, see USAGE_GUIDE.md")
    input("\nPress Enter to continue...")

def test_examples():
    """Test with example files"""
    clear_screen()
    print("🧪 Test with Example Files")
    print("-" * 35)
    
    examples_dir = "examples"
    if not os.path.exists(examples_dir):
        print(f"\n❌ Examples directory not found: {examples_dir}")
        input("Press Enter to continue...")
        return
    
    # Find example images
    example_files = [f for f in os.listdir(examples_dir) 
                    if f.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp'))]
    
    if not example_files:
        print(f"\n❌ No example images found in {examples_dir}")
        input("Press Enter to continue...")
        return
    
    print(f"\n🧪 Found {len(example_files)} example files:")
    for i, file in enumerate(example_files, 1):
        print(f"   {i}. {file}")
    
    print("\n🔍 Running analysis on example files...")
    
    for example_file in example_files:
        file_path = os.path.join(examples_dir, example_file)
        print(f"\n🔍 Analyzing: {example_file}")
        
        stdout, stderr, returncode = run_command(f"python advanced_stego.py \"{file_path}\"")
        if returncode == 0:
            # Show key findings
            lines = stdout.split('\n')
            for line in lines:
                if '⚠️' in line or '✅' in line or 'message found' in line.lower():
                    print(f"   {line}")
        else:
            print(f"   ❌ Error: {stderr}")
    
    print("\n🧪 Test complete! Try hiding your own message:")
    print("   python stego_detector.py hide examples/ORIGINAL.jpg --message \"test\" --output my_test.jpg")
    
    input("\nPress Enter to continue...")

def main():
    """Main function"""
    if not check_virtual_env():
        activate_virtual_env()
    
    menu()

if __name__ == "__main__":
    main()
