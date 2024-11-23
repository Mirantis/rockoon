#!/usr/bin/env python3
import argparse
import asyncio
import sys

from rockoon import kube


def parse_args():
    parser = argparse.ArgumentParser(
        prog="osctl-job-rerun", description="Delete and re-create a job"
    )
    parser.add_argument("name", help=("Job name"))
    parser.add_argument("namespace", help=("Job's namespace"))
    return parser.parse_args()


def main():
    args = parse_args()
    job = kube.find(kube.Job, args.name, args.namespace, silent=True)
    if not job:
        sys.exit(f"Job {args.namespace}/{args.name} was not found!")
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(job.rerun())
    except Exception as e:
        sys.exit(f"Failed to create job {job.namespace}/{job.name}: {e}")
