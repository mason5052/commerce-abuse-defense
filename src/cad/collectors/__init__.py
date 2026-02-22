"""Data collectors for ingesting eCommerce event data from various platforms."""

from cad.collectors.base import BaseCollector
from cad.collectors.sample import SampleCollector

__all__ = ["BaseCollector", "SampleCollector"]
