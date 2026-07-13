#!/usr/bin/env python3
"""
Steganography Detection and Extraction Tool
A simple Python-based steganography analysis toolkit
"""

import os
import sys
import argparse
from PIL import Image, ImageChops
import numpy as np
import matplotlib.pyplot as plt
from stegano import lsb
import cv2

def analyze_image_metadata(image_path):
    """Analyze image metadata for potential steganography indicators"""
    try:
        img = Image.open(image_path)
        print(f"\n=== Image Analysis: {image_path} ===")
        print(f"Format: {img.format}")
        print(f"Size: {img.size}")
        print(f"Mode: {img.mode}")
        
        # Check for unusual aspects
        if hasattr(img, 'info'):
            if img.info:
                print(f"Metadata: {img.info}")
            else:
                print("No metadata found")
        
        return img
    except Exception as e:
        print(f"Error analyzing image: {e}")
        return None

def lsb_analysis(image_path):
    """Perform LSB (Least Significant Bit) analysis"""
    try:
        print(f"\n=== LSB Analysis ===")
        
        # Try to extract hidden message using stegano
        try:
            hidden_message = lsb.reveal(image_path)
            if hidden_message:
                print(f"Hidden message found: {hidden_message}")
                return hidden_message
            else:
                print("No LSB hidden message detected")
        except Exception as e:
            print(f"LSB reveal failed: {e}")
        
        # Visual LSB analysis
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        img_array = np.array(img)
        
        # Extract LSB from each color channel
        lsb_r = img_array[:,:,0] & 1
        lsb_g = img_array[:,:,1] & 1
        lsb_b = img_array[:,:,2] & 1
        
        # Create LSB visualization
        lsb_combined = (lsb_r * 0.299 + lsb_g * 0.587 + lsb_b * 0.114) * 255
        lsb_image = Image.fromarray(lsb_combined.astype(np.uint8), mode='L')
        
        lsb_output_path = f"{os.path.splitext(image_path)[0]}_lsb_analysis.png"
        lsb_image.save(lsb_output_path)
        print(f"LSB analysis saved to: {lsb_output_path}")
        
        return None
    except Exception as e:
        print(f"Error in LSB analysis: {e}")
        return None

def steganography_detection(image_path):
    """Comprehensive steganography detection"""
    print(f"\n{'='*50}")
    print(f"STEGANOGRAPHY DETECTION FOR: {image_path}")
    print(f"{'='*50}")
    
    # Basic image analysis
    img = analyze_image_metadata(image_path)
    if not img:
        return
    
    # LSB analysis
    lsb_analysis(image_path)
    
    # Statistical analysis
    print(f"\n=== Statistical Analysis ===")
    img_array = np.array(img)
    print(f"Mean pixel values: R:{np.mean(img_array[:,:,0]):.2f}, G:{np.mean(img_array[:,:,1]):.2f}, B:{np.mean(img_array[:,:,2]):.2f}")
    print(f"Std deviation: R:{np.std(img_array[:,:,0]):.2f}, G:{np.std(img_array[:,:,1]):.2f}, B:{np.std(img_array[:,:,2]):.2f}")
    
    # Check for suspicious patterns
    print(f"\n=== Pattern Analysis ===")
    
    # Check for repeated patterns (might indicate hidden data)
    unique_colors = len(np.unique(img_array.reshape(-1, 3), axis=0))
    total_pixels = img_array.shape[0] * img_array.shape[1]
    print(f"Unique colors: {unique_colors:,} out of {total_pixels:,} pixels")
    print(f"Color diversity: {(unique_colors/total_pixels)*100:.2f}%")
    
    if unique_colors < total_pixels * 0.1:
        print("WARNING: Low color diversity - possible steganography indicator")

def hide_message_lsb(image_path, message, output_path):
    """Hide a message using LSB steganography"""
    try:
        secret_img = lsb.hide(image_path, message)
        secret_img.save(output_path)
        print(f"Message hidden in: {output_path}")
        return True
    except Exception as e:
        print(f"Error hiding message: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Steganography Detection and Extraction Tool')
    parser.add_argument('action', choices=['detect', 'hide', 'extract'], help='Action to perform')
    parser.add_argument('image', help='Path to image file')
    parser.add_argument('--message', help='Message to hide (for hide action)')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    if args.action == 'detect':
        if not os.path.exists(args.image):
            print(f"Error: Image file {args.image} not found")
            return
        steganography_detection(args.image)
    
    elif args.action == 'hide':
        if not args.message or not args.output:
            print("Error: --message and --output required for hide action")
            return
        if not os.path.exists(args.image):
            print(f"Error: Image file {args.image} not found")
            return
        hide_message_lsb(args.image, args.message, args.output)
    
    elif args.action == 'extract':
        if not os.path.exists(args.image):
            print(f"Error: Image file {args.image} not found")
            return
        lsb_analysis(args.image)

if __name__ == "__main__":
    main()
