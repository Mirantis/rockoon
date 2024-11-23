#!/usr/bin/env python3
#    Copyright 2023 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import abc
from datetime import datetime
import sys
from threading import Thread, Lock
import time

from prometheus_client.core import GaugeMetricFamily

from rockoon.exporter import settings
from rockoon.exporter import collectors
from rockoon import utils
from rockoon import kube


LOG = utils.get_logger(__name__)


class OsdplMetricsCollector(object):
    def __init__(self):
        self.collector_instances = []
        self.gather_tasks = {}
        self.max_poll_timeout = settings.OSCTL_EXPORTER_MAX_POLL_TIMEOUT
        for name, collector in collectors.registry.items():
            if name in settings.OSCTL_EXPORTER_ENABLED_COLLECTORS:
                LOG.info(f"Adding collector {name} to registry")
                instance = collector()
                self.collector_instances.append(instance)
        self.init_tasks_status_tread()
        self.initialized = False

    def init_tasks_status_tread(self):
        LOG.info(f"Starting tasks status thread.")
        future = Thread(target=self.watch_for_tasks, daemon=True)
        future.start()
        self.status_future = future

    def watch_for_tasks(self):
        while True:
            self.update_tasks_status()
            time.sleep(5)

    def submit_task(self, name, func):
        """Submit a taks with data collection

        :param name: The name of task to start
        :param func: function to run in tread
        :return: False if task is already running, True otherwise.
        """
        start = datetime.utcnow()
        if name in self.gather_tasks:
            running_for = start - self.gather_tasks[name]["started_at"]
            LOG.warning(
                f"The task {name} already running for {running_for}. Highly likely this occur due to frequent metric collection."
            )
            return False
        LOG.info(f"Starting metric collector thread for {name}")
        future = Thread(target=func)
        self.gather_tasks[name] = {"future": future, "started_at": start}
        future.start()
        return True

    def complete_task(self, name):
        self.gather_tasks.pop(name)

    def check_stuck_tasks(self):
        for name, task in self.gather_tasks.copy().items():
            if (
                datetime.utcnow() - task["started_at"]
            ).total_seconds() > self.max_poll_timeout:
                LOG.error(
                    f"Task {name} stuck for more than {self.max_poll_timeout}."
                )
                sys.exit(1)

    def update_tasks_status(self):
        for name, task in self.gather_tasks.copy().items():
            future = task["future"]
            if not future.is_alive():
                took_time = datetime.utcnow() - task["started_at"]
                self.complete_task(name)
                LOG.info(f"Task {name} took {took_time} to complete.")
        self.check_stuck_tasks()

    def wait_for_tasks(self, timeout):
        start = datetime.utcnow()
        while any(
            [
                task["future"].is_alive()
                for task in self.gather_tasks.copy().values()
            ]
        ):
            if (datetime.utcnow() - start).total_seconds() >= timeout:
                LOG.warning(
                    f"Tasks {self.gather_tasks.copy()} did not complete in {timeout}, return cache result."
                )
                return
            time.sleep(1)

    def collect(self):
        osdpl = kube.get_osdpl()
        if not self.status_future.is_alive():
            LOG.error("The status task is not running.")
            sys.exit(1)

        if not osdpl:
            return
        if self.initialized:
            if osdpl:
                LOG.info(f"The osdpl {osdpl.name} found. Collecting metrics")
                for collector_instance in self.collector_instances:
                    self.submit_task(
                        collector_instance._name,
                        collector_instance.refresh_data,
                    )
            self.wait_for_tasks(settings.OSCTL_SCRAPE_TIMEOUT)
        self.initialized = True
        scrape_duration = GaugeMetricFamily(
            "osdpl_scrape_collector_duration_seconds",
            "Durations in seconds taken by collector to refresh metrics.",
            labels=["collector"],
        )
        scrape_sucess = GaugeMetricFamily(
            "osdpl_scrape_collector_success",
            "Flag inidicates if collector was able to refresh metrics successfully.",
            labels=["collector"],
        )
        scrape_start_timestamp = GaugeMetricFamily(
            "osdpl_scrape_collector_start_timestamp",
            "Unix timestamp when collector metrics refresh was started.",
            labels=["collector"],
        )
        scrape_end_timestamp = GaugeMetricFamily(
            "osdpl_scrape_collector_end_timestamp",
            "Unix timestamp when collector metrics refresh was finished.",
            labels=["collector"],
        )

        for collector_instance in self.collector_instances:
            if collector_instance.can_collect:
                yield from collector_instance.collect()
                scrape_duration.add_metric(
                    [collector_instance._name],
                    collector_instance.scrape_duration,
                )
                scrape_sucess.add_metric(
                    [collector_instance._name],
                    collector_instance.scrape_success,
                )
                scrape_start_timestamp.add_metric(
                    [collector_instance._name],
                    collector_instance.scrape_start_timestamp,
                )
                scrape_end_timestamp.add_metric(
                    [collector_instance._name],
                    collector_instance.scrape_end_timestamp,
                )
        yield scrape_duration
        yield scrape_sucess
        yield scrape_start_timestamp
        yield scrape_end_timestamp


class BaseMetricsCollector(object):
    _name = "osdpl_metric_name"
    _description = "osdpl metric description"
    registry = {}

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        cls.registry[cls._name] = cls

    def __init__(self):
        self.can_collect = False
        self.scrape_duration = 0
        self.scrape_success = False
        self.scrape_start_timestamp = 0
        self.scrape_end_timestamp = 0
        self.lock_samples = Lock()
        self.families = self.init_families()

    def init_families(self):
        """Return all known collector metric families"""
        return {}

    def set_samples(self, name, samples):
        """Sets metric samples on falimy"""
        with self.lock_samples:
            self.families[name].samples = []
            for sample in samples:
                self.families[name].add_metric(*sample)

    def collect(self):
        with self.lock_samples:
            for name, metric in self.families.items():
                yield metric

    @abc.abstractmethod
    def update_samples(self):
        """Long running task for taking data."""
        pass

    def refresh_data(self):
        LOG.info(f"Started refreshing data for {self._name}")
        start = datetime.utcnow()
        self.scrape_start_timestamp = start.timestamp()
        self.scrape_end_timestamp = 0
        try:
            self.osdpl = kube.get_osdpl()
            self.can_collect = self.can_collect_data
            if not self.can_collect:
                LOG.warning(
                    f"Collector {self._name} is enabled, but collection for it is not possible."
                )
                return
            self.update_samples()
            self.scrape_success = True
        except Exception as e:
            self.scrape_success = False
            LOG.exception(e)
        now = datetime.utcnow()
        self.scrape_end_timestamp = now.timestamp()
        self.scrape_duration = (now - start).total_seconds()
        LOG.info(f"Finished refreshing data for {self._name}")

    @property
    @abc.abstractmethod
    def can_collect_data(self):
        pass
