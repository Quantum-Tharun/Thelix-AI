"""
Thelix AI — Durable Background Scan Worker CLI Entry Point
Executes as a standalone process polling the relational outbox for asynchronous scans.

Usage:
    python -m app.worker [--poll-interval 2.0] [--lease-seconds 300] [--once] [--worker-id <id>]
"""
import sys
import asyncio
import argparse
import signal
import logging

from app.config import settings
from app.services.scan_worker import DurableScanWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("thelix.worker.main")


def parse_args():
    parser = argparse.ArgumentParser(description="Thelix AI Background Scan Worker Daemon")
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds when queue is idle (default: 2.0)",
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=300,
        help="Lease duration in seconds for claimed tasks (default: 300)",
    )
    parser.add_argument(
        "--worker-id",
        type=str,
        default=None,
        help="Optional unique worker identifier (default: auto-generated)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process all currently available tasks until the queue is empty, then exit.",
    )
    return parser.parse_args()


async def main():
    args = parse_args()
    worker = DurableScanWorker(
        worker_id=args.worker_id,
        lease_duration_seconds=args.lease_seconds,
        poll_interval_seconds=args.poll_interval,
    )

    if args.once:
        logger.info(f"Running worker '{worker.worker_id}' in batch-once mode...")
        processed_count = 0
        while True:
            processed = await worker.process_one()
            if not processed:
                break
            processed_count += 1
        logger.info(f"Worker '{worker.worker_id}' finished batch-once mode; processed {processed_count} tasks.")
        return

    stop_event = asyncio.Event()

    def handle_signal(sig, frame):
        logger.info(f"Received shutdown signal {sig}; initiating graceful stop...")
        stop_event.set()
        worker.stop()

    try:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
    except Exception:
        # Some signals may not be registerable on Windows non-main threads
        pass

    try:
        await worker.run_loop(stop_event=stop_event)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Worker interrupted by user; shutting down.")
    finally:
        worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
