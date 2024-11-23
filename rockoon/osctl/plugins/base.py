#!/usr/bin/env python3
import abc


class OsctlShell:
    name = ""
    description = ""
    registry = {}

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        cls.registry[cls.name] = cls

    def __init__(self, parser, subparsers):
        self.parser = parser
        self.subparsers = subparsers
        self.pl_parser = self.subparsers.add_parser(
            self.name, help=self.description
        )

    @abc.abstractmethod
    def build_options(self):
        pass

    def run(self, args):
        getattr(self, args.sub_subcommand)(args)
