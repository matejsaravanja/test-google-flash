# craft-nft-marketplace/backend/tests/test_nft_generator.py
import pytest
from app.nft_generator import generate_unique_nft
def test_generate_unique_nft():
    svg = generate_unique_nft('test_nft_id') #Test example
    assert isinstance(svg, str)
    assert '<svg' in svg