#!/usr/bin/env python3

import os

from opensearchpy import OpenSearch

from rockoon.osctl.plugins import constants
from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl import utils as osctl_utils
from rockoon import utils

LOG = utils.get_logger(__name__)


class ElasticLogsCollector(base.BaseLogsCollector):
    name = "elastic"

    def __init__(self, args, workspace, mode):
        super().__init__(args, workspace, mode)
        self.elastic_url = args.elastic_url
        self.elastic_query_size = args.elastic_query_size
        self.elastic_index_name = args.elastic_index_name
        self.loggers = self.get_loggers(self.components)
        self.between = args.between or f"now-{args.since},now"
        self.http_auth = None
        if self.args.elastic_username and self.args.elastic_password:
            self.http_auth = (
                self.args.elastic_username,
                self.args.elastic_password,
            )

    def get_hosts(self):
        if self.args.all_hosts:
            # NOTE(vsaienko): skip discovery via kubernetes
            # get host directly from elastic/opensearch.
            return [None]
        return super().get_hosts()

    def get_loggers(self, components):
        loggers = set()
        for component in set(components):
            for logger in constants.OSCTL_COMPONENT_LOGGERS.get(
                component, [component]
            ):
                loggers.add(logger)
        return loggers

    def query_logger(self, logger):
        return {
            "bool": {
                "should": [
                    {
                        "simple_query_string": {
                            "fields": ["event.provider"],
                            "query": f"{logger}*",
                        }
                    }
                ],
                "minimum_should_match": 1,
            }
        }

    def query_message(self, phrase):
        return {
            "bool": {
                "should": [{"match_phrase": {"message": phrase}}],
                "minimum_should_match": 1,
            }
        }

    def query_host(self, host):
        return {
            "bool": {
                "should": [{"match_phrase": {"host.hostname": host}}],
                "minimum_should_match": 1,
            }
        }

    def query_timestamp(self, between="now-1w,now"):
        """Returns opensearch timestamp filter expression

        :param between: string meaning period between absolute or relative
                        timestamps. Possible formats:
                        2024-08-12T10:23,2024-08-12T10:30
                        2024-08-11,2024-08-12
                        now-2h,now-1h

        https://opensearch.org/docs/2.0/opensearch/supported-field-types/date/
        """

        start, end = between.split(",")
        return {"range": {"@timestamp": {"gte": start, "lte": end}}}

    def get_query(self, logger, host=None, message=None, between="now-1w,now"):
        filters = [
            {"match_all": {}},
            self.query_logger(logger),
            self.query_timestamp(between),
        ]
        if host is not None:
            filters.append(self.query_host(host))
        if message is not None:
            filters.append(self.query_message(message))
        return {
            "size": self.elastic_query_size,
            "sort": [
                {
                    "@timestamp": {
                        "order": "asc",
                    }
                }
            ],
            "query": {
                "bool": {
                    "must": [],
                    "filter": filters,
                    "should": [],
                    "must_not": [],
                }
            },
        }

    @osctl_utils.generic_exception
    def collect_logs(
        self, logger, host=None, message=None, between="now-1w,now"
    ):
        msg = f"Starting logs collection for {host} {logger}"
        if host is None:
            msg = f"Starting logs collection for all hosts {logger}"
        LOG.info(msg)
        client = OpenSearch(
            [self.elastic_url],
            timeout=60,
            http_auth=self.http_auth,
            http_compress=True,
        )
        query = self.get_query(
            logger, host=host, message=message, between=between
        )
        response = client.search(
            body=query, index=self.elastic_index_name, request_timeout=60
        )
        while len(response["hits"]["hits"]):
            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                if source.get("orchestrator", {}).get("type") != "kubernetes":
                    continue
                ts = source["@timestamp"]
                level = source.get("log", {}).get("level", "UNKNOWN")
                message = source.get("message", "UNCNOWN")
                pod_name = source.get("orchestrator", {}).get("pod", "UNCNOWN")
                container_name = source.get("container", {}).get(
                    "name", "UNCNOWN"
                )
                host = source.get("host", {}).get("hostname", "UNKNOWN")
                logs_dst_base = os.path.join(self.workspace, host, pod_name)
                os.makedirs(logs_dst_base, exist_ok=True)
                logs_dst = os.path.join(
                    self.workspace, host, pod_name, container_name
                )
                msg = f"{ts} {level} {message}"
                with open(logs_dst, "a") as f:
                    f.write(msg)
                    if not msg.endswith("\n"):
                        f.write("\n")
            search_after = response["hits"]["hits"][-1]["sort"]
            query["search_after"] = search_after
            response = client.search(body=query, index=self.elastic_index_name)
        LOG.info(f"Successfully collected logs for {host} {logger}")

    def get_tasks(self):
        res = []
        message = None
        if self.mode == "trace" and self.args.message:
            message = self.args.message
        for host in self.hosts:
            for logger in self.loggers:
                res.append(
                    (
                        self.collect_logs,
                        (logger,),
                        {
                            "host": host,
                            "between": self.between,
                            "message": message,
                        },
                    )
                )
        return res
