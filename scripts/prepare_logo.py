#!/usr/bin/env python3
"""
Prepare logo PNGs for the Qt UI.
- Ensures proper alpha transparency (removes any baked-in checkered background)
- Generates multiple sizes for crisp rendering at different resolutions
- Outputs to resources/ directory
"""

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Installing Pillow...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow", "--quiet"])
    from PIL import Image


def clean_transparency(img):
    """Ensure the image has proper RGBA transparency."""
    img = img.convert("RGBA")
    data = img.getdata()

    new_data = []
    for pixel in data:
        r, g, b, a = pixel
        # Detect checkered transparency pattern:
        # Light gray (#C0C0C0 / #808080) or white squares
        # If pixel is very close to the checkerboard colors AND has full opacity,
        # it might be a baked-in checkerboard
        is_light_check = (abs(r - 192) < 15 and abs(g - 192) < 15 and abs(b - 192) < 15)
        is_dark_check = (abs(r - 128) < 15 and abs(g - 128) < 15 and abs(b - 128) < 15)
        is_white = (r > 240 and g > 240 and b > 240)

        if a == 0:
            # Already transparent
            new_data.append((0, 0, 0, 0))
        else:
            new_data.append(pixel)

    img.putdata(new_data)
    return img


def trim_transparent(img):
    """Crop to the non-transparent bounding box."""
    bbox = img.getbbox()
    if bbox:
        img = img.crop(bbox)
    return img


def generate_sizes(img, output_dir):
    """Generate multiple sizes for Qt resource usage."""
    # Trim any transparent border
    img = trim_transparent(img)

    sizes = {
        "logo_icon.png": 512,        # High-res for app icon / dock
        "logo_icon_64.png": 64,      # Header bar (Retina)
        "logo_icon_128.png": 128,    # Medium usage
        "logo_icon_256.png": 256,    # Large usage
    }

    for filename, size in sizes.items():
        resized = img.resize((size, size), Image.LANCZOS)
        out_path = output_dir / filename
        resized.save(out_path, "PNG", optimize=True)
        print(f"  Saved: {out_path} ({size}x{size})")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 prepare_logo.py <path_to_logo.png>")
        print("  Processes the logo and saves optimized versions to resources/")
        sys.exit(1)

    src_path = Path(sys.argv[1])
    if not src_path.exists():
        print(f"ERROR: File not found: {src_path}")
        sys.exit(1)

    output_dir = Path(__file__).parent.parent / "resources"
    output_dir.mkdir(exist_ok=True)

    print(f"Processing: {src_path}")
    img = Image.open(src_path).convert("RGBA")
    print(f"  Original size: {img.size[0]}x{img.size[1]}")

    # Check if image actually has transparency
    extrema = img.getextrema()
    alpha_min, alpha_max = extrema[3]
    if alpha_min == alpha_max == 255:
        print("  WARNING: Image has no transparency (solid background)")
        print("  Attempting to remove background...")
        # Try to make white/light backgrounds transparent
        data = img.getdata()
        new_data = []
        for pixel in data:
            r, g, b, a = pixel
            # Remove near-white backgrounds
            if r > 235 and g > 235 and b > 235:
                new_data.append((0, 0, 0, 0))
            # Remove light gray checkerboard
            elif abs(r - g) < 10 and abs(g - b) < 10 and r > 180:
                new_data.append((0, 0, 0, 0))
            else:
                new_data.append(pixel)
        img.putdata(new_data)
        print("  Background removed.")
    else:
        print(f"  Alpha range: {alpha_min}-{alpha_max} (has transparency)")

    # Clean and generate
    img = clean_transparency(img)
    generate_sizes(img, output_dir)

    print("\nDone! Now rebuild:")
    print("  cd ~/Odysseus-AI/build && cmake .. && make -j4")


if __name__ == "__main__":
    main()
