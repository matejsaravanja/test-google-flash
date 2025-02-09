# craft-nft-marketplace/backend/app/nft_generator.py
import svgwrite
import random
import hashlib

def generate_unique_nft(seed: str):
    """Generates a unique SVG NFT based on a seed.

    Args:
        seed: A string used to ensure uniqueness (e.g., transaction hash).

    Returns:
        A string containing the SVG data.
    """

    random.seed(seed) #Seed the num gen so images come out consistent for download

    width, height = 200, 200
    dwg = svgwrite.Drawing(filename='nft.svg', size=(width, height))

    # Generate random colors
    bg_color = f"rgb({random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)})"
    circle_color = f"rgb({random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)})"
    text_color = f"rgb({random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)})"

    # Draw background
    dwg.add(dwg.rect(insert=(0, 0), size=(width, height), fill=bg_color))

    # Draw a circle
    circle_x = width / 2
    circle_y = height / 2
    circle_radius = width / 4
    dwg.add(dwg.circle(center=(circle_x, circle_y), r=circle_radius, fill=circle_color))

    # Add text with the seed
    dwg.add(dwg.text(seed[:8], insert=(width/2 - 30, height - 20 ), fill=text_color)) #Show a bit of the seed

    return dwg.tostring()