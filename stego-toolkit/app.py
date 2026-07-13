#!/usr/bin/env python3
"""
Steganography Detection Toolkit - Web Interface
A Flask-based web application for steganography analysis
"""

import os
import sys
import tempfile
import traceback
import secrets
import string
import re
import socket
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import numpy as np
from PIL import Image
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import io
import base64
from stegano import lsb, exifHeader
import scipy.fft as fft
from scipy import stats
import wave
import struct
import json
from datetime import datetime
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64 as b64
import urllib.parse

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff', 'tif', 'wav', 'mp3'}

# Analysis history storage
ANALYSIS_HISTORY = []
MAX_HISTORY = 50

# Cryptography functions
def generate_hash(text, algorithm='sha256'):
    """Generate hash of text using specified algorithm"""
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    if algorithm not in algorithms:
        return {'error': f'Algorithm {algorithm} not supported'}
    
    try:
        hash_obj = algorithms[algorithm](text.encode())
        return {
            'algorithm': algorithm,
            'hash': hash_obj.hexdigest(),
            'input_length': len(text)
        }
    except Exception as e:
        return {'error': str(e)}

def encode_decode(text, operation, method):
    """Encode or decode text using various methods"""
    try:
        if method == 'base64':
            if operation == 'encode':
                result = base64.b64encode(text.encode()).decode()
            else:
                result = base64.b64decode(text).decode()
        elif method == 'url':
            if operation == 'encode':
                result = urllib.parse.quote(text)
            else:
                result = urllib.parse.unquote(text)
        elif method == 'hex':
            if operation == 'encode':
                result = text.encode().hex()
            else:
                result = bytes.fromhex(text).decode()
        elif method == 'binary':
            if operation == 'encode':
                result = ' '.join(format(ord(c), '08b') for c in text)
            else:
                result = ''.join(chr(int(b, 2)) for b in text.split())
        else:
            return {'error': f'Method {method} not supported'}
        
        return {
            'operation': operation,
            'method': method,
            'result': result,
            'input_length': len(text),
            'output_length': len(result)
        }
    except Exception as e:
        return {'error': str(e)}

def caesar_cipher(text, shift, operation):
    """Caesar cipher encryption/decryption"""
    try:
        result = ''
        shift = int(shift)
        
        if operation == 'decrypt':
            shift = -shift
        
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        
        return {
            'operation': operation,
            'shift': shift,
            'result': result
        }
    except Exception as e:
        return {'error': str(e)}

def vigenere_cipher(text, key, operation):
    """Vigenère cipher encryption/decryption"""
    try:
        result = ''
        key = key.upper()
        key_index = 0
        
        if operation == 'decrypt':
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    key_char = key[key_index % len(key)]
                    key_shift = ord(key_char) - 65
                    result += chr((ord(char) - ascii_offset - key_shift) % 26 + ascii_offset)
                    key_index += 1
                else:
                    result += char
        else:
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    key_char = key[key_index % len(key)]
                    key_shift = ord(key_char) - 65
                    result += chr((ord(char) - ascii_offset + key_shift) % 26 + ascii_offset)
                    key_index += 1
                else:
                    result += char
        
        return {
            'operation': operation,
            'key': key,
            'result': result
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_password_strength(password):
    """Analyze password strength"""
    try:
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append('Password should be at least 8 characters long')
        
        if len(password) >= 12:
            score += 1
        
        # Complexity checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append('Add lowercase letters')
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append('Add uppercase letters')
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append('Add numbers')
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append('Add special characters')
        
        # Common patterns
        if re.search(r'(.)\1{2,}', password):
            score -= 1
            feedback.append('Avoid repeated characters')
        
        if password.lower() in ['password', '123456', 'qwerty', 'admin']:
            score = 0
            feedback.append('Password is too common')
        
        # Determine strength
        if score <= 2:
            strength = 'Weak'
            color = '#ff0000'
        elif score <= 4:
            strength = 'Medium'
            color = '#ffff00'
        else:
            strength = 'Strong'
            color = '#00ff00'
        
        # Calculate entropy
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        if charset_size > 0:
            entropy = len(password) * (charset_size.bit_length() - 1)
        else:
            entropy = 0
        
        return {
            'strength': strength,
            'score': min(max(score, 0), 6),
            'entropy': round(entropy, 2),
            'feedback': feedback,
            'length': len(password)
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_ip(ip_address):
    """Analyze IP address"""
    try:
        # Validate IP
        try:
            socket.inet_aton(ip_address)
        except socket.error:
            return {'error': 'Invalid IP address'}
        
        result = {
            'ip': ip_address,
            'version': 'IPv4',
            'is_private': ip_address.startswith(('10.', '172.16.', '192.168.', '127.')),
            'is_loopback': ip_address.startswith('127.'),
            'is_multicast': ip_address.startswith('224.') or ip_address.startswith('239.')
        }
        
        # Try to get hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            result['hostname'] = hostname
        except:
            result['hostname'] = 'Not available'
        
        return result
    except Exception as e:
        return {'error': str(e)}

def scan_ports(ip_address, ports=None):
    """Scan common ports on an IP address (limited scan)"""
    try:
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 8080]
        
        results = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    results.append({
                        'port': port,
                        'status': 'open',
                        'service': get_service_name(port)
                    })
            except:
                pass
        
        return {
            'ip': ip_address,
            'scanned_ports': len(ports),
            'open_ports': len(results),
            'results': results
        }
    except Exception as e:
        return {'error': str(e)}

def get_service_name(port):
    """Get common service name for port"""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 443: 'HTTPS',
        445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 8080: 'HTTP-Alt'
    }
    return services.get(port, 'Unknown')

def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def file_entropy_analysis(file_path):
    """Calculate file entropy to detect hidden data"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Calculate entropy
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        byte_probs = byte_counts / len(data)
        entropy = -np.sum(byte_probs * np.log2(byte_probs + 1e-10))
        
        return {
            'file_size': len(data),
            'entropy': round(entropy, 4),
            'status': 'high' if entropy > 7.5 else 'low' if entropy < 6.0 else 'normal',
            'message': 'High entropy - possible encrypted/hidden data' if entropy > 7.5 else 
                      'Low entropy - possible repetitive patterns' if entropy < 6.0 else 
                      'Normal entropy range'
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_image_metadata(file_path):
    """Analyze image metadata"""
    try:
        img = Image.open(file_path)
        metadata = {
            'format': img.format,
            'size': img.size,
            'mode': img.mode,
            'info': dict(img.info) if hasattr(img, 'info') and img.info else {}
        }
        
        # Check for suspicious metadata
        suspicious = []
        for key, value in metadata['info'].items():
            if isinstance(value, str) and len(value) > 100:
                suspicious.append(f"Large metadata field '{key}'")
        
        return {
            'metadata': metadata,
            'suspicious': suspicious,
            'status': 'warning' if suspicious else 'normal'
        }
    except Exception as e:
        return {'error': str(e)}

def lsb_analysis(file_path):
    """Perform LSB analysis"""
    try:
        # Try to extract hidden message
        hidden_message = lsb.reveal(file_path)
        
        # Create LSB visualization
        img = Image.open(file_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        img_array = np.array(img)
        lsb_r = img_array[:,:,0] & 1
        lsb_g = img_array[:,:,1] & 1
        lsb_b = img_array[:,:,2] & 1
        
        # Create LSB visualization
        lsb_combined = (lsb_r * 0.299 + lsb_g * 0.587 + lsb_b * 0.114) * 255
        lsb_image = Image.fromarray(lsb_combined.astype(np.uint8), mode='L')
        
        # Convert to base64 for web display
        buffer = io.BytesIO()
        lsb_image.save(buffer, format='PNG')
        lsb_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'hidden_message': hidden_message if hidden_message else None,
            'lsb_image': f'data:image/png;base64,{lsb_base64}',
            'message_found': hidden_message is not None
        }
    except Exception as e:
        return {'error': str(e)}

def chi_square_lsb_test(img_array):
    """Chi-square test for LSB steganography detection"""
    try:
        # Extract LSB planes
        lsb_plane = img_array & 1
        
        # Count occurrences of each value in LSB plane
        unique, counts = np.unique(lsb_plane, return_counts=True)
        
        # Expected distribution for random data
        total_pixels = lsb_plane.size
        expected = total_pixels / 2
        
        # Calculate chi-square statistic
        chi_square = np.sum((counts - expected) ** 2 / expected)
        
        # Critical value for 1 degree of freedom at 95% confidence
        critical_value = 3.841
        
        return {
            'chi_square': round(chi_square, 4),
            'critical_value': critical_value,
            'lsb_detected': chi_square > critical_value,
            'message': 'LSB steganography likely detected' if chi_square > critical_value else 'No LSB steganography detected'
        }
    except Exception as e:
        return {'error': str(e)}

def rs_analysis(img_array):
    """RS (Regular-Singular) analysis for steganography detection"""
    try:
        # Simple RS analysis implementation
        # This is a simplified version of the full RS analysis
        
        # Calculate noise levels in different pixel groups
        h_diff = np.diff(img_array, axis=1)  # Horizontal differences
        v_diff = np.diff(img_array, axis=0)  # Vertical differences
        
        h_variance = np.var(h_diff)
        v_variance = np.var(v_diff)
        
        # Regular groups (low variance)
        regular_groups = np.sum((h_diff < 2) & (v_diff < 2))
        
        # Singular groups (high variance)
        singular_groups = np.sum((h_diff > 5) & (v_diff > 5))
        
        total_groups = h_diff.size
        
        rs_ratio = regular_groups / (singular_groups + 1)
        
        # High RS ratio may indicate steganography
        return {
            'rs_ratio': round(rs_ratio, 4),
            'regular_groups': int(regular_groups),
            'singular_groups': int(singular_groups),
            'stego_detected': rs_ratio > 3.0,
            'message': 'Possible steganography detected (high RS ratio)' if rs_ratio > 3.0 else 'Normal RS ratio'
        }
    except Exception as e:
        return {'error': str(e)}

def frequency_domain_analysis(img_array):
    """FFT-based frequency domain analysis"""
    try:
        # Convert to grayscale if needed
        if len(img_array.shape) == 3:
            gray = np.mean(img_array, axis=2)
        else:
            gray = img_array
        
        # Apply 2D FFT
        fft_result = fft.fft2(gray)
        fft_shifted = fft.fftshift(fft_result)
        
        # Calculate magnitude spectrum
        magnitude_spectrum = np.abs(fft_shifted)
        
        # Calculate phase spectrum
        phase_spectrum = np.angle(fft_shifted)
        
        # Analyze high-frequency components (potential steganography indicator)
        h, w = magnitude_spectrum.shape
        center_h, center_w = h // 2, w // 2
        
        # Extract high-frequency region
        high_freq_region = magnitude_spectrum[center_h-50:center_h+50, center_w-50:center_w+50]
        high_freq_energy = np.sum(high_freq_region)
        total_energy = np.sum(magnitude_spectrum)
        high_freq_ratio = high_freq_energy / total_energy
        
        # Create visualization
        log_magnitude = np.log(1 + magnitude_spectrum)
        normalized_mag = (log_magnitude - log_magnitude.min()) / (log_magnitude.max() - log_magnitude.min())
        
        buffer = io.BytesIO()
        plt.imsave(buffer, normalized_mag * 255, cmap='viridis', format='PNG')
        fft_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'high_freq_ratio': round(high_freq_ratio, 6),
            'total_energy': round(float(total_energy), 2),
            'high_freq_energy': round(float(high_freq_energy), 2),
            'anomaly_detected': high_freq_ratio > 0.001,
            'fft_image': f'data:image/png;base64,{fft_base64}',
            'message': 'High-frequency anomaly detected' if high_freq_ratio > 0.001 else 'Normal frequency distribution'
        }
    except Exception as e:
        return {'error': str(e)}

def color_channel_analysis(img_array):
    """Analyze individual color channels"""
    try:
        if len(img_array.shape) != 3:
            return {'error': 'Image must be RGB'}
        
        results = {}
        channels = ['Red', 'Green', 'Blue']
        
        for i, channel_name in enumerate(channels):
            channel_data = img_array[:, :, i]
            
            # Calculate channel-specific statistics
            results[f'{channel_name.lower()}_mean'] = round(float(np.mean(channel_data)), 2)
            results[f'{channel_name.lower()}_std'] = round(float(np.std(channel_data)), 2)
            results[f'{channel_name.lower()}_entropy'] = round(float(calculate_entropy(channel_data)), 4)
            
            # LSB analysis for this channel
            channel_lsb = channel_data & 1
            lsb_ratio = np.sum(channel_lsb) / channel_data.size
            results[f'{channel_name.lower()}_lsb_ratio'] = round(lsb_ratio, 4)
        
        # Check for channel anomalies
        r_entropy = results['red_entropy']
        g_entropy = results['green_entropy']
        b_entropy = results['blue_entropy']
        
        entropy_diff = max(r_entropy, g_entropy, b_entropy) - min(r_entropy, g_entropy, b_entropy)
        
        results['entropy_difference'] = round(entropy_diff, 4)
        results['channel_anomaly'] = entropy_diff > 0.5
        results['anomaly_message'] = 'Channel entropy anomaly detected' if entropy_diff > 0.5 else 'Normal channel distribution'
        
        return results
    except Exception as e:
        return {'error': str(e)}

def calculate_entropy(data):
    """Calculate entropy of data array"""
    try:
        if len(data.shape) == 2:
            data = data.flatten()
        
        byte_counts = np.bincount(data.astype(np.uint8), minlength=256)
        byte_probs = byte_counts / len(data)
        entropy = -np.sum(byte_probs * np.log2(byte_probs + 1e-10))
        return entropy
    except:
        return 0.0

def histogram_analysis(img_array):
    """Analyze color histograms"""
    try:
        if len(img_array.shape) == 3:
            # RGB histogram
            histograms = []
            for i in range(3):
                hist, _ = np.histogram(img_array[:, :, i], bins=256, range=(0, 256))
                histograms.append(hist)
            
            # Calculate histogram statistics
            results = {
                'red_peaks': int(np.argmax(histograms[0])),
                'green_peaks': int(np.argmax(histograms[1])),
                'blue_peaks': int(np.argmax(histograms[2])),
                'red_std': round(float(np.std(histograms[0])), 2),
                'green_std': round(float(np.std(histograms[1])), 2),
                'blue_std': round(float(np.std(histograms[2])), 2)
            }
            
            # Check for histogram anomalies
            avg_std = np.mean([results['red_std'], results['green_std'], results['blue_std']])
            results['avg_std'] = round(float(avg_std), 2)
            results['histogram_anomaly'] = avg_std < 50
            results['anomaly_message'] = 'Histogram anomaly detected (low variance)' if avg_std < 50 else 'Normal histogram distribution'
            
            return results
        else:
            # Grayscale histogram
            hist, _ = np.histogram(img_array, bins=256, range=(0, 256))
            return {
                'peak': int(np.argmax(hist)),
                'std': round(float(np.std(hist)), 2),
                'histogram_anomaly': np.std(hist) < 50
            }
    except Exception as e:
        return {'error': str(e)}

def audio_analysis(file_path):
    """Analyze audio files for steganography"""
    try:
        if file_path.lower().endswith('.wav'):
            return analyze_wav(file_path)
        elif file_path.lower().endswith('.mp3'):
            return {'error': 'MP3 analysis not fully supported, use WAV files'}
        else:
            return {'error': 'Unsupported audio format'}
    except Exception as e:
        return {'error': str(e)}

def analyze_wav(file_path):
    """Analyze WAV file for steganography"""
    try:
        with wave.open(file_path, 'rb') as wav_file:
            params = wav_file.getparams()
            frames = wav_file.readframes(params.nframes)
            
        # Convert to numpy array
        if params.sampwidth == 2:
            dtype = np.int16
        elif params.sampwidth == 4:
            dtype = np.int32
        else:
            dtype = np.int8
            
        audio_data = np.frombuffer(frames, dtype=dtype)
        
        # Calculate audio entropy
        audio_entropy = calculate_entropy(audio_data)
        
        # LSB analysis for audio
        audio_lsb = audio_data & 1
        lsb_ratio = np.sum(audio_lsb) / len(audio_lsb)
        
        # Frequency analysis
        fft_result = fft.fft(audio_data)
        magnitude = np.abs(fft_result)
        
        # Check for high-frequency anomalies
        n = len(magnitude)
        high_freq = magnitude[n//4:3*n//4]
        high_freq_energy = np.sum(high_freq)
        total_energy = np.sum(magnitude)
        high_freq_ratio = high_freq_energy / total_energy
        
        return {
            'channels': params.nchannels,
            'sample_width': params.sampwidth,
            'frame_rate': params.framerate,
            'num_frames': params.nframes,
            'duration': round(params.nframes / params.framerate, 2),
            'entropy': round(audio_entropy, 4),
            'lsb_ratio': round(lsb_ratio, 4),
            'high_freq_ratio': round(high_freq_ratio, 6),
            'stego_detected': audio_entropy > 7.5 or lsb_ratio > 0.55,
            'message': 'Possible audio steganography detected' if (audio_entropy > 7.5 or lsb_ratio > 0.55) else 'Normal audio characteristics'
        }
    except Exception as e:
        return {'error': str(e)}

def statistical_analysis(file_path):
    """Perform comprehensive statistical analysis"""
    try:
        img = Image.open(file_path).convert('RGB')
        img_array = np.array(img)
        
        # Basic statistics
        results = {
            'mean_r': round(float(np.mean(img_array[:,:,0])), 2),
            'mean_g': round(float(np.mean(img_array[:,:,1])), 2),
            'mean_b': round(float(np.mean(img_array[:,:,2])), 2),
            'std_r': round(float(np.std(img_array[:,:,0])), 2),
            'std_g': round(float(np.std(img_array[:,:,1])), 2),
            'std_b': round(float(np.std(img_array[:,:,2])), 2)
        }
        
        # Color diversity
        unique_colors = len(np.unique(img_array.reshape(-1, 3), axis=0))
        total_pixels = img_array.shape[0] * img_array.shape[1]
        diversity = (unique_colors / total_pixels) * 100
        
        results['unique_colors'] = unique_colors
        results['total_pixels'] = total_pixels
        results['diversity'] = round(diversity, 2)
        results['diversity_status'] = 'warning' if diversity < 10 else 'normal'
        
        # Additional advanced tests
        chi_square = chi_square_lsb_test(img_array)
        rs = rs_analysis(img_array)
        
        results.update({
            'chi_square': chi_square,
            'rs_analysis': rs
        })
        
        return results
    except Exception as e:
        return {'error': str(e)}

def hide_message_lsb(image_path, message, output_path):
    """Hide a message using LSB steganography"""
    try:
        secret_img = lsb.hide(image_path, message)
        secret_img.save(output_path)
        return True, None
    except Exception as e:
        return False, str(e)

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and comprehensive analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Calculate file hash for identification
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        
        # Perform analysis
        results = {
            'filename': filename,
            'file_path': file_path,
            'file_hash': file_hash,
            'analysis_timestamp': datetime.now().isoformat(),
            'file_type': 'image' if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif')) else 'audio'
        }
        
        # File entropy analysis
        entropy_results = file_entropy_analysis(file_path)
        results['entropy'] = entropy_results
        
        # Image-specific analysis
        if results['file_type'] == 'image':
            try:
                img = Image.open(file_path).convert('RGB')
                img_array = np.array(img)
                
                # Metadata analysis
                metadata_results = analyze_image_metadata(file_path)
                results['metadata'] = metadata_results
                
                # LSB analysis
                lsb_results = lsb_analysis(file_path)
                results['lsb'] = lsb_results
                
                # Statistical analysis (includes chi-square and RS)
                stat_results = statistical_analysis(file_path)
                results['statistics'] = stat_results
                
                # Frequency domain analysis
                try:
                    freq_results = frequency_domain_analysis(img_array)
                    results['frequency_analysis'] = freq_results
                except Exception as e:
                    results['frequency_analysis'] = {'error': str(e)}
                
                # Color channel analysis
                try:
                    channel_results = color_channel_analysis(img_array)
                    results['channel_analysis'] = channel_results
                except Exception as e:
                    results['channel_analysis'] = {'error': str(e)}
                
                # Histogram analysis
                try:
                    hist_results = histogram_analysis(img_array)
                    results['histogram_analysis'] = hist_results
                except Exception as e:
                    results['histogram_analysis'] = {'error': str(e)}
                
            except Exception as e:
                results['image_analysis_error'] = str(e)
        
        # Audio-specific analysis
        elif results['file_type'] == 'audio':
            try:
                audio_results = audio_analysis(file_path)
                results['audio_analysis'] = audio_results
            except Exception as e:
                results['audio_analysis'] = {'error': str(e)}
        
        # Add to analysis history
        analysis_entry = {
            'filename': filename,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'file_type': results['file_type'],
            'entropy': float(entropy_results.get('entropy', 0)),
            'stego_detected': bool(any([
                entropy_results.get('status') == 'high',
                results.get('statistics', {}).get('chi_square', {}).get('lsb_detected', False),
                results.get('statistics', {}).get('rs_analysis', {}).get('stego_detected', False),
                results.get('frequency_analysis', {}).get('anomaly_detected', False),
                results.get('channel_analysis', {}).get('channel_anomaly', False),
                results.get('audio_analysis', {}).get('stego_detected', False)
            ]))
        }
        
        ANALYSIS_HISTORY.append(analysis_entry)
        if len(ANALYSIS_HISTORY) > MAX_HISTORY:
            ANALYSIS_HISTORY.pop(0)
        
        # Convert numpy types to Python types for JSON serialization
        def convert_to_serializable(obj):
            if isinstance(obj, dict):
                return {key: convert_to_serializable(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_serializable(item) for item in obj]
            elif isinstance(obj, (np.integer, np.int64, np.int32)):
                return int(obj)
            elif isinstance(obj, (np.floating, np.float64, np.float32)):
                return float(obj)
            elif isinstance(obj, np.bool_):
                return bool(obj)
            elif isinstance(obj, np.ndarray):
                return convert_to_serializable(obj.tolist())
            else:
                return obj
        
        results = convert_to_serializable(results)
        return jsonify(results)
    
    except Exception as e:
        import traceback
        return jsonify({'error': f'Server error: {str(e)}', 'traceback': traceback.format_exc()}), 500

@app.route('/hide', methods=['POST'])
def hide_message():
    """Hide a message in an image"""
    if 'file' not in request.files or 'message' not in request.form:
        return jsonify({'error': 'Missing file or message'}), 400
    
    file = request.files['file']
    message = request.form['message']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    if not message.strip():
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(input_path)
    
    # Create output filename
    name, ext = os.path.splitext(filename)
    output_filename = f"{name}_stego{ext}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    
    # Hide message
    success, error = hide_message_lsb(input_path, message, output_path)
    
    if success:
        return jsonify({
            'success': True,
            'output_filename': output_filename,
            'message': 'Message hidden successfully!'
        })
    else:
        return jsonify({'error': error}), 500

@app.route('/download/<filename>')
def download_file(filename):
    """Download a file"""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Steganography Detection Toolkit is running'})

@app.route('/history')
def get_history():
    """Get analysis history"""
    return jsonify({'history': ANALYSIS_HISTORY})

@app.route('/history/clear', methods=['POST'])
def clear_history():
    """Clear analysis history"""
    global ANALYSIS_HISTORY
    ANALYSIS_HISTORY = []
    return jsonify({'message': 'History cleared'})

@app.route('/batch', methods=['POST'])
def batch_upload():
    """Handle batch file upload and analysis"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files uploaded'}), 400
        
        files = request.files.getlist('files')
        if not files or files[0].filename == '':
            return jsonify({'error': 'No files selected'}), 400
        
        results = []
        for file in files:
            if not allowed_file(file.filename):
                results.append({'filename': file.filename, 'error': 'File type not allowed'})
                continue
            
            try:
                # Save uploaded file
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Calculate file hash
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                
                # Perform analysis
                file_result = {
                    'filename': filename,
                    'file_hash': file_hash,
                    'file_type': 'image' if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif')) else 'audio'
                }
                
                # Entropy analysis
                entropy_results = file_entropy_analysis(file_path)
                file_result['entropy'] = entropy_results
                
                # Image-specific analysis
                if file_result['file_type'] == 'image':
                    try:
                        img = Image.open(file_path).convert('RGB')
                        img_array = np.array(img)
                        
                        # Quick statistical analysis
                        stat_results = {
                            'mean_r': round(float(np.mean(img_array[:,:,0])), 2),
                            'mean_g': round(float(np.mean(img_array[:,:,1])), 2),
                            'mean_b': round(float(np.mean(img_array[:,:,2])), 2),
                            'diversity': round(len(np.unique(img_array.reshape(-1, 3), axis=0)) / (img_array.shape[0] * img_array.shape[1]) * 100, 2)
                        }
                        file_result['statistics'] = stat_results
                        
                        # Chi-square test
                        chi_results = chi_square_lsb_test(img_array)
                        file_result['chi_square'] = chi_results
                        
                    except Exception as e:
                        file_result['error'] = str(e)
                
                # Audio analysis
                elif file_result['file_type'] == 'audio':
                    audio_results = audio_analysis(file_path)
                    file_result['audio_analysis'] = audio_results
                
                results.append(file_result)
                
            except Exception as e:
                results.append({'filename': file.filename, 'error': str(e)})
        
        # Convert numpy types to Python types for JSON serialization
        def convert_to_serializable(obj):
            if isinstance(obj, dict):
                return {key: convert_to_serializable(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_serializable(item) for item in obj]
            elif isinstance(obj, (np.integer, np.int64, np.int32)):
                return int(obj)
            elif isinstance(obj, (np.floating, np.float64, np.float32)):
                return float(obj)
            elif isinstance(obj, np.bool_):
                return bool(obj)
            elif isinstance(obj, np.ndarray):
                return convert_to_serializable(obj.tolist())
            else:
                return obj
        
        results = convert_to_serializable(results)
        return jsonify({'results': results, 'total_files': len(results)})
    
    except Exception as e:
        import traceback
        return jsonify({'error': f'Server error: {str(e)}', 'traceback': traceback.format_exc()}), 500

@app.route('/hide/advanced', methods=['POST'])
def hide_message_advanced():
    """Hide message with different methods"""
    if 'file' not in request.files or 'message' not in request.form:
        return jsonify({'error': 'Missing file or message'}), 400
    
    file = request.files['file']
    message = request.form['message']
    method = request.form.get('method', 'lsb')  # lsb, red, lsb-set
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    if not message.strip():
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(input_path)
    
    # Create output filename
    name, ext = os.path.splitext(filename)
    output_filename = f"{name}_{method}_stego{ext}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    
    try:
        if method == 'lsb':
            from stegano import lsb
            secret_img = lsb.hide(input_path, message)
            secret_img.save(output_path)
        elif method == 'red':
            from stegano.lsb import lsb
            from stegano import red
            secret_img = red.hide(input_path, message)
            secret_img.save(output_path)
        else:
            # Default to LSB
            from stegano import lsb
            secret_img = lsb.hide(input_path, message)
            secret_img.save(output_path)
        
        return jsonify({
            'success': True,
            'output_filename': output_filename,
            'method': method,
            'message': f'Message hidden successfully using {method.upper()} method!'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Cryptography and Security Routes
@app.route('/crypto/hash', methods=['POST'])
def crypto_hash():
    """Generate hash of text"""
    try:
        data = request.json
        text = data.get('text', '')
        algorithm = data.get('algorithm', 'sha256')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        result = generate_hash(text, algorithm)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/crypto/encode', methods=['POST'])
def crypto_encode():
    """Encode text using various methods"""
    try:
        data = request.json
        text = data.get('text', '')
        method = data.get('method', 'base64')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        result = encode_decode(text, 'encode', method)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/crypto/decode', methods=['POST'])
def crypto_decode():
    """Decode text using various methods"""
    try:
        data = request.json
        text = data.get('text', '')
        method = data.get('method', 'base64')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        result = encode_decode(text, 'decode', method)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/crypto/caesar', methods=['POST'])
def crypto_caesar():
    """Caesar cipher encryption/decryption"""
    try:
        data = request.json
        text = data.get('text', '')
        shift = data.get('shift', 3)
        operation = data.get('operation', 'encrypt')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        result = caesar_cipher(text, shift, operation)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/crypto/vigenere', methods=['POST'])
def crypto_vigenere():
    """Vigenère cipher encryption/decryption"""
    try:
        data = request.json
        text = data.get('text', '')
        key = data.get('key', '')
        operation = data.get('operation', 'encrypt')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        if not key:
            return jsonify({'error': 'Key is required'}), 400
        
        result = vigenere_cipher(text, key, operation)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/security/password', methods=['POST'])
def security_password():
    """Analyze password strength"""
    try:
        data = request.json
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        result = analyze_password_strength(password)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/security/ip', methods=['POST'])
def security_ip():
    """Analyze IP address"""
    try:
        data = request.json
        ip_address = data.get('ip', '')
        
        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400
        
        result = analyze_ip(ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/security/portscan', methods=['POST'])
def security_portscan():
    """Scan ports on IP address"""
    try:
        data = request.json
        ip_address = data.get('ip', '')
        
        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400
        
        result = scan_ports(ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Steganography Detection Toolkit Web Interface...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔍 Ready to detect steganography!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
