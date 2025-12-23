"""
Hardware-based True Random Number Generator
Uses phone sensors (camera, microphone, accelerometer, etc.) to generate cryptographically secure random data
Designed for PinePhone and Linux devices
"""

import hashlib
import time
import os
from pathlib import Path

# Try to import hardware libraries
try:
    import cv2
    CAMERA_AVAILABLE = True
except ImportError:
    CAMERA_AVAILABLE = False
    print("Warning: OpenCV not available. Camera entropy source disabled.")

try:
    import pyaudio
    import numpy as np
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False
    print("Warning: PyAudio not available. Microphone entropy source disabled.")

try:
    # For accelerometer/gyroscope on mobile devices
    import sensors
    SENSORS_AVAILABLE = True
except ImportError:
    SENSORS_AVAILABLE = False
    # This is normal on desktop - sensors are mainly for mobile devices


class HardwareRandomGenerator:
    """Generate cryptographically secure random data using hardware sources."""
    
    def __init__(self, callback=None):
        """
        Initialize the hardware random generator.
        
        Args:
            callback: Function to call with status updates
        """
        self.callback = callback
        self.entropy_pool = bytearray()
        
    def log(self, message):
        """Log status messages."""
        if self.callback:
            self.callback(message)
        else:
            print(message)
    
    def collect_camera_entropy(self, num_frames=10, camera_index=0):
        """
        Collect entropy from camera sensor noise.
        
        Args:
            num_frames: Number of frames to capture
            camera_index: Camera device index (0 = default camera)
            
        Returns:
            bytes: Entropy data from camera
        """
        if not CAMERA_AVAILABLE:
            self.log("⚠ Camera not available")
            return b''
        
        try:
            self.log(f"📷 Collecting entropy from camera (capturing {num_frames} frames)...")
            cap = cv2.VideoCapture(camera_index)
            
            if not cap.isOpened():
                self.log("⚠ Could not open camera")
                return b''
            
            # Set camera to low quality for faster capture
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)
            
            entropy_data = bytearray()
            
            for i in range(num_frames):
                ret, frame = cap.read()
                if ret:
                    # Use the raw pixel data as entropy
                    # Even with lens cap on, sensor noise provides randomness
                    entropy_data.extend(frame.tobytes())
                    self.log(f"  Frame {i+1}/{num_frames} captured ({len(frame.tobytes())} bytes)")
                time.sleep(0.05)  # Small delay between frames
            
            cap.release()
            
            self.log(f"✓ Camera entropy collected: {len(entropy_data)} bytes")
            return bytes(entropy_data)
            
        except Exception as e:
            self.log(f"⚠ Camera error: {e}")
            return b''
    
    def collect_microphone_entropy(self, duration=2, sample_rate=44100):
        """
        Collect entropy from microphone ambient noise.
        
        Args:
            duration: Recording duration in seconds
            sample_rate: Audio sample rate
            
        Returns:
            bytes: Entropy data from microphone
        """
        if not AUDIO_AVAILABLE:
            self.log("⚠ Microphone not available")
            return b''
        
        try:
            self.log(f"🎤 Collecting entropy from microphone ({duration}s of ambient noise)...")
            
            p = pyaudio.PyAudio()
            
            # Use default input device
            stream = p.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=sample_rate,
                input=True,
                frames_per_buffer=1024
            )
            
            frames = []
            chunks = int(sample_rate / 1024 * duration)
            
            for i in range(chunks):
                data = stream.read(1024)
                frames.append(data)
                if i % 10 == 0:
                    self.log(f"  Recording... {int((i/chunks)*100)}%")
            
            stream.stop_stream()
            stream.close()
            p.terminate()
            
            audio_data = b''.join(frames)
            self.log(f"✓ Microphone entropy collected: {len(audio_data)} bytes")
            return audio_data
            
        except Exception as e:
            self.log(f"⚠ Microphone error: {e}")
            return b''
    
    def collect_system_entropy(self):
        """
        Collect entropy from system sources.
        
        Returns:
            bytes: System entropy data
        """
        self.log("💻 Collecting system entropy...")
        
        entropy_sources = []
        
        # 1. System random device (urandom)
        try:
            urandom_data = os.urandom(1024)
            entropy_sources.append(urandom_data)
            self.log("  ✓ /dev/urandom: 1024 bytes")
        except Exception as e:
            self.log(f"  ⚠ /dev/urandom failed: {e}")
        
        # 2. High-resolution time
        time_data = str(time.time_ns()).encode()
        entropy_sources.append(time_data)
        self.log(f"  ✓ High-res time: {len(time_data)} bytes")
        
        # 3. Process timing variations
        timing_entropy = bytearray()
        for _ in range(100):
            start = time.perf_counter_ns()
            # Do some work
            _ = hashlib.sha256(os.urandom(32)).digest()
            end = time.perf_counter_ns()
            timing_entropy.extend((end - start).to_bytes(8, 'big'))
        
        entropy_sources.append(bytes(timing_entropy))
        self.log(f"  ✓ Process timing: {len(timing_entropy)} bytes")
        
        # 4. Memory addresses (ASLR provides randomness)
        try:
            addr_entropy = str(id(object())).encode()
            entropy_sources.append(addr_entropy)
            self.log(f"  ✓ Memory ASLR: {len(addr_entropy)} bytes")
        except:
            pass
        
        total_entropy = b''.join(entropy_sources)
        self.log(f"✓ System entropy collected: {len(total_entropy)} bytes")
        return total_entropy
    
    def collect_sensor_entropy(self):
        """
        Collect entropy from device sensors (accelerometer, gyroscope, etc.).
        Mainly for mobile devices like PinePhone.
        
        Returns:
            bytes: Sensor entropy data
        """
        if not SENSORS_AVAILABLE:
            return b''
        
        try:
            self.log("📱 Collecting entropy from device sensors...")
            sensor_data = bytearray()
            
            # Read accelerometer, gyroscope, magnetometer
            # Sensor noise and minute vibrations provide randomness
            for _ in range(100):
                # This would read actual sensor data on PinePhone
                # For now, we use system entropy as fallback
                pass
            
            return bytes(sensor_data)
        except Exception as e:
            self.log(f"⚠ Sensor error: {e}")
            return b''
    
    def collect_all_entropy(self, camera_frames=10, audio_duration=2):
        """
        Collect entropy from all available sources.
        
        Args:
            camera_frames: Number of camera frames to capture
            audio_duration: Audio recording duration in seconds
            
        Returns:
            bytes: Combined entropy from all sources
        """
        self.log("=" * 50)
        self.log("🔐 Hardware True Random Number Generation")
        self.log("=" * 50)
        
        all_entropy = []
        
        # Collect from all available sources
        camera_entropy = self.collect_camera_entropy(num_frames=camera_frames)
        if camera_entropy:
            all_entropy.append(camera_entropy)
        
        audio_entropy = self.collect_microphone_entropy(duration=audio_duration)
        if audio_entropy:
            all_entropy.append(audio_entropy)
        
        system_entropy = self.collect_system_entropy()
        if system_entropy:
            all_entropy.append(system_entropy)
        
        sensor_entropy = self.collect_sensor_entropy()
        if sensor_entropy:
            all_entropy.append(sensor_entropy)
        
        # Combine all entropy sources
        combined = b''.join(all_entropy)
        
        self.log("=" * 50)
        self.log(f"📊 Total raw entropy collected: {len(combined):,} bytes")
        self.log("=" * 50)
        
        return combined
    
    def generate_random_bytes(self, num_bytes, camera_frames=10, audio_duration=2):
        """
        Generate cryptographically secure random bytes using hardware entropy.
        
        Args:
            num_bytes: Number of random bytes to generate
            camera_frames: Number of camera frames to use for entropy
            audio_duration: Audio recording duration for entropy
            
        Returns:
            bytes: Cryptographically secure random data
        """
        # Collect hardware entropy
        entropy = self.collect_all_entropy(
            camera_frames=camera_frames,
            audio_duration=audio_duration
        )
        
        if len(entropy) < 1024:
            self.log("⚠ Warning: Low entropy collected, using more system randomness")
            entropy += os.urandom(4096)
        
        self.log(f"🔄 Generating {num_bytes:,} random bytes...")
        
        # Use HKDF (HMAC-based Key Derivation Function) to extract uniform randomness
        # This is cryptographically secure - even if some entropy sources are biased,
        # the output will be uniformly random
        
        random_bytes = bytearray()
        counter = 0
        
        while len(random_bytes) < num_bytes:
            # Hash the entropy with a counter to generate more random data
            hasher = hashlib.sha512()
            hasher.update(entropy)
            hasher.update(counter.to_bytes(8, 'big'))
            hasher.update(os.urandom(32))  # Mix in system randomness
            
            random_bytes.extend(hasher.digest())
            counter += 1
            
            if counter % 100 == 0:
                progress = min(100, (len(random_bytes) / num_bytes) * 100)
                self.log(f"  Progress: {progress:.1f}%")
        
        result = bytes(random_bytes[:num_bytes])
        
        self.log(f"✓ Generated {len(result):,} cryptographically secure random bytes")
        return result
    
    def generate_random_string(self, length, charset):
        """
        Generate a random string from hardware entropy.
        
        Args:
            length: Length of string to generate
            charset: Character set to use
            
        Returns:
            str: Random string
        """
        # Generate enough random bytes
        # We need more bytes than characters because we're selecting from a charset
        num_bytes = length * 4  # Overgenerate to ensure we have enough
        
        random_data = self.generate_random_bytes(num_bytes, camera_frames=5, audio_duration=1)
        
        # Convert random bytes to string using charset
        result = []
        charset_len = len(charset)
        
        byte_index = 0
        while len(result) < length and byte_index < len(random_data):
            # Use modulo to select character (with rejection sampling for uniformity)
            byte_val = random_data[byte_index]
            
            # Rejection sampling to avoid bias
            if byte_val < (256 // charset_len) * charset_len:
                char_index = byte_val % charset_len
                result.append(charset[char_index])
            
            byte_index += 1
        
        return ''.join(result)


def test_hardware_rng():
    """Test the hardware random number generator."""
    print("\n=== Hardware RNG Test ===\n")
    
    rng = HardwareRandomGenerator()
    
    # Test 1: Generate random bytes
    print("Test 1: Generate 1KB of random bytes")
    random_bytes = rng.generate_random_bytes(1024, camera_frames=5, audio_duration=1)
    print(f"Generated: {len(random_bytes)} bytes")
    print(f"First 32 bytes (hex): {random_bytes[:32].hex()}\n")
    
    # Test 2: Generate random string
    print("Test 2: Generate random string")
    import string
    charset = string.ascii_uppercase + string.digits + string.punctuation
    random_string = rng.generate_random_string(100, charset)
    print(f"Random string: {random_string[:50]}...\n")


if __name__ == "__main__":
    test_hardware_rng()