#!/usr/bin/env python3
"""
Advanced Steganography Detection Tool
Includes multiple detection methods and analysis techniques
"""

import os
import sys
import argparse
import numpy as np
from PIL import Image, ImageChops, ImageStat
import matplotlib.pyplot as plt
from stegano import lsb, exifHeader
import cv2
import hashlib

def file_entropy_analysis(file_path):
    """Calculate file entropy to detect hidden data"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Calculate entropy
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        byte_probs = byte_counts / len(data)
        entropy = -np.sum(byte_probs * np.log2(byte_probs + 1e-10))
        
        print(f"\n=== File Entropy Analysis ===")
        print(f"File size: {len(data):,} bytes")
        print(f"Entropy: {entropy:.4f}")
        
        if entropy > 7.5:
            print("WARNING: High entropy - possible encrypted/hidden data")
        elif entropy < 6.0:
            print("WARNING: Low entropy - possible repetitive patterns")
        else:
            print("OK: Normal entropy range")
            
        return entropy
    except Exception as e:
        print(f"Error in entropy analysis: {e}")
        return 0

def chi_square_test(image_path):
    """Chi-square test for LSB steganography detection"""
    try:
        img = Image.open(image_path).convert('RGB')
        img_array = np.array(img)
        
        # Calculate chi-square for each color channel
        chi_scores = []
        for channel in range(3):
            channel_data = img_array[:,:,channel].flatten()
            
            # Count pairs of values that differ only in LSB
            pairs = {}
            for pixel in channel_data:
                base_val = pixel >> 1  # Remove LSB
                if base_val not in pairs:
                    pairs[base_val] = [0, 0]  # [even_count, odd_count]
                
                if pixel % 2 == 0:
                    pairs[base_val][0] += 1
                else:
                    pairs[base_val][1] += 1
            
            # Calculate chi-square for each pair
            chi_values = []
            for even_count, odd_count in pairs.values():
                total = even_count + odd_count
                if total > 0:
                    expected = total / 2
                    chi = ((even_count - expected)**2 + (odd_count - expected)**2) / expected
                    chi_values.append(chi)
            
            if chi_values:
                chi_scores.append(np.mean(chi_values))
        
        avg_chi = np.mean(chi_scores) if chi_scores else 0
        
        print(f"\n=== Chi-Square LSB Test ===")
        print(f"Average chi-square value: {avg_chi:.4f}")
        
        if avg_chi > 3.84:  # Critical value for df=1 at 95% confidence
            print("WARNING: High chi-square - possible LSB steganography")
        else:
            print("OK: Chi-square test normal")
            
        return avg_chi
    except Exception as e:
        print(f"Error in chi-square test: {e}")
        return 0

def rs_analysis(image_path):
    """Regular/Singleton (RS) analysis for steganography detection"""
    try:
        img = Image.open(image_path).convert('L')  # Convert to grayscale
        img_array = np.array(img)
        
        # Define regular and singular groups
        def is_regular(group):
            return (group[0] - group[1]) * (group[1] - group[2]) > 0
        
        def is_singular(group):
            return (group[0] - group[1]) * (group[1] - group[2]) < 0
        
        # Count regular and singular groups
        regular_count = 0
        singular_count = 0
        total_groups = 0
        
        height, width = img_array.shape
        
        # Horizontal groups
        for i in range(height):
            for j in range(width - 2):
                group = img_array[i, j:j+3]
                if is_regular(group):
                    regular_count += 1
                elif is_singular(group):
                    singular_count += 1
                total_groups += 1
        
        # Vertical groups
        for i in range(height - 2):
            for j in range(width):
                group = img_array[i:i+3, j]
                if is_regular(group):
                    regular_count += 1
                elif is_singular(group):
                    singular_count += 1
                total_groups += 1
        
        if total_groups > 0:
            regular_ratio = regular_count / total_groups
            singular_ratio = singular_count / total_groups
            
            print(f"\n=== RS Analysis ===")
            print(f"Total groups analyzed: {total_groups:,}")
            print(f"Regular groups: {regular_count:,} ({regular_ratio:.2%})")
            print(f"Singular groups: {singular_count:,} ({singular_ratio:.2%})")
            
            # RS steganography typically increases the number of regular groups
            if regular_ratio > 0.45:
                print("WARNING: High regular group ratio - possible steganography")
            else:
                print("OK: RS analysis normal")
                
            return regular_ratio
    except Exception as e:
        print(f"Error in RS analysis: {e}")
        return 0

def histogram_analysis(image_path):
    """Histogram analysis for steganography detection"""
    try:
        img = Image.open(image_path).convert('RGB')
        img_array = np.array(img)
        
        print(f"\n=== Histogram Analysis ===")
        
        for i, color in enumerate(['Red', 'Green', 'Blue']):
            channel = img_array[:,:,i]
            hist, bins = np.histogram(channel, bins=256, range=(0, 256))
            
            # Calculate histogram smoothness
            smoothness = np.sum(np.abs(np.diff(hist)))
            print(f"{color} channel smoothness: {smoothness:.0f}")
            
            # Check for unusual patterns
            if smoothness > 10000:
                print(f"WARNING: {color} channel shows irregular patterns")
        
        return True
    except Exception as e:
        print(f"Error in histogram analysis: {e}")
        return False

def extract_metadata(image_path):
    """Extract and analyze EXIF metadata"""
    try:
        img = Image.open(image_path)
        
        print(f"\n=== Metadata Analysis ===")
        
        if hasattr(img, '_getexif') and img._getexif():
            exif_data = img._getexif()
            for tag_id, value in exif_data.items():
                tag_name = f"Tag {tag_id}"
                print(f"{tag_name}: {value}")
        else:
            print("No EXIF data found")
        
        # Check for unusual metadata
        if hasattr(img, 'info') and img.info:
            for key, value in img.info.items():
                print(f"{key}: {value}")
                
                # Check for suspicious metadata values
                if isinstance(value, str) and len(value) > 100:
                    print(f"WARNING: Large metadata field '{key}' - potential hidden data")
                    
    except Exception as e:
        print(f"Error in metadata analysis: {e}")

def comprehensive_analysis(image_path):
    """Run all steganography detection methods"""
    print(f"\n{'='*60}")
    print(f"COMPREHENSIVE STEGANOGRAPHY ANALYSIS")
    print(f"File: {image_path}")
    print(f"{'='*60}")
    
    if not os.path.exists(image_path):
        print(f"Error: File {image_path} not found")
        return
    
    # Run all detection methods
    file_entropy_analysis(image_path)
    chi_square_test(image_path)
    rs_analysis(image_path)
    histogram_analysis(image_path)
    extract_metadata(image_path)
    
    # Try to extract hidden messages
    print(f"\n=== Message Extraction Attempts ===")
    
    try:
        # LSB extraction
        hidden_message = lsb.reveal(image_path)
        if hidden_message:
            print(f"FOUND: LSB message found: {hidden_message}")
        else:
            print("No LSB message detected")
    except:
        print("LSB extraction failed")
    
    try:
        # EXIF header extraction
        exif_message = exifHeader.reveal(image_path)
        if exif_message:
            print(f"FOUND: EXIF message found: {exif_message}")
        else:
            print("No EXIF message detected")
    except:
        print("EXIF extraction failed")

def main():
    parser = argparse.ArgumentParser(description='Advanced Steganography Detection Tool')
    parser.add_argument('image', help='Path to image file')
    parser.add_argument('--entropy-only', action='store_true', help='Only perform entropy analysis')
    parser.add_argument('--lsb-only', action='store_true', help='Only perform LSB analysis')
    
    args = parser.parse_args()
    
    if args.entropy_only:
        file_entropy_analysis(args.image)
    elif args.lsb_only:
        chi_square_test(args.image)
        rs_analysis(args.image)
        try:
            hidden_message = lsb.reveal(args.image)
            if hidden_message:
                print(f"Hidden message: {hidden_message}")
            else:
                print("No LSB message detected")
        except:
            print("LSB extraction failed")
    else:
        comprehensive_analysis(args.image)

if __name__ == "__main__":
    main()
