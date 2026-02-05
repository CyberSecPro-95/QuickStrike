"""
Global Shutdown Event - Hard Kill Implementation
"""

import asyncio

# Global shutdown event for immediate termination
shutdown_event = asyncio.Event()
