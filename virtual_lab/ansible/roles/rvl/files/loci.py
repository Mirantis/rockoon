#!/usr/bin/env python3

import argparse
import logging
import yaml
import os
import subprocess
import sys

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from concurrent.futures import ALL_COMPLETED

colorlog = None

try:
    import colorlog
except ImportError:
    pass

LOG = logging.getLogger("")
LOG.setLevel(logging.DEBUG)
sh = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    "[%(asctime)s] %(levelname)s %(message)s", datefmt="%a, %d %b %Y %H:%M:%S"
)
if colorlog:
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s %(asctime)s %(levelname)s %(message)s",
        datefmt="%a, %d %b %Y %H:%M:%S",
    )
sh.setFormatter(formatter)
LOG.addHandler(sh)


class LociBuilder:

    def __init__(self, parser):
        self.parser = parser
        self.subcommand = self.parser.subcommand
        self.conf = self.load_conf()
        self.loci_path = self.parser.loci_path

    def load_conf(self):
        with open(self.parser.config) as f:
            return yaml.safe_load(f)

    @property
    def projects(self):
        return set(self.conf.get("builder", {}).get("projects", []))

    def image_full_name(self, name):
        tag = self.parser.image_tag
        image = os.path.join(self.parser.image_path, name)
        return f"{image}:{tag}"

    def get_build_args(self, name):
        project_config = (
            self.conf.get("builder", {}).get("projects_configs", {}).get(name, {})
        )
        res = ["--build-arg", f"PROJECT={name}"]
        for arg_name, arg_value in project_config.get("docker_build_args", {}).items():
            res.append("--build-arg")
            res.append(f"{arg_name}={arg_value}")
        if name != "requirements":
            image_full_name = self.image_full_name("requirements")
            res.extend(["--build-arg", f"WHEELS={image_full_name}"])
        return res

    def should_build(self, name):
        return name in self.projects

    def run(self):
        return getattr(self, self.subcommand)()

    def run_cmd(self, cmd, hide_stdout=True):
        stdout = stderr = subprocess.STDOUT
        if hide_stdout:
            stdout = subprocess.DEVNULL
        return subprocess.run(cmd, stdout=stdout)

    def is_image_exists(self, name):
        image_full_name = self.image_full_name(name)
        cmd = ["docker", "image", "inspect", image_full_name]
        res = self.run_cmd(cmd)
        return res.returncode == 0

    def build_project(self, name):
        image_full_name = self.image_full_name(name)
        if not self.is_image_exists(name):
            build_cmd = ["docker", "build", "--tag", image_full_name]
            build_cmd.extend(self.get_build_args(name))
            build_cmd.extend([self.loci_path])
            LOG.info("Building project %s", name)
            LOG.info(build_cmd)
            subprocess.run(build_cmd, check=True)
        else:
            LOG.info(
                "Skipped building project %s. Image %s exists.", name, image_full_name
            )
        if self.parser.push:
            self.push_project(name)

    def push_project(self, name):
        image_full_name = self.image_full_name(name)
        publish_cmd = ["docker", "push", image_full_name]
        LOG.info("Pushing project %s", image_full_name)
        LOG.info(publish_cmd)
        self.run_cmd(publish_cmd)

    def push(self):
        for project in self.projects:
            self.push_project(name)

    def build(self):
        build_concurrency = self.parser.concurrency
        executor = ThreadPoolExecutor(max_workers=build_concurrency)

        if self.should_build("requirements"):
            self.build_project("requirements")
        futures = {}
        for project in self.projects - set(["requirements"]):
            futures[project] = executor.submit(self.build_project, project)
        done, not_done = wait(futures.values(), return_when=ALL_COMPLETED)
        failed = []
        for project, future in futures.items():
            if future.done():
                exception = future.exception()
                if exception:
                    failed.append(project)
                    LOG.error("Building %s failed with: %s", project, exception)
        if failed:
            LOG.error("Building %s images failed.", failed)
            sys.exit(1)

    def clone(self):
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        description="Client to build docker images with loci."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    build = subparsers.add_parser("build", help="Build subparser")
    parser.add_argument(
        "--config",
        required=True,
        help="Specify the path to build configuration",
    )
    parser.add_argument(
        "--loci-path",
        required=False,
        default=os.path.dirname(os.path.realpath(__file__)),
        help="Path to loci project",
    )
    build.add_argument(
        "--push",
        required=False,
        action="store_true",
        default=False,
        help="Push image to registry",
    )
    build.add_argument(
        "--image-path",
        required=True,
        help="Specify path where we will store image",
    )
    build.add_argument(
        "--image-tag",
        required=True,
        help="Tag to assign to image",
    )

    build.add_argument(
        "--concurrency",
        required=False,
        type=int,
        help="Concurrency for parallel builds",
        default=3,
    )

    return parser.parse_args()


def main():
    args = parse_args()
    lb = LociBuilder(args)
    lb.run()


if __name__ == "__main__":
    main()
