import json

from collections import defaultdict
from itertools import groupby

from rockoon.tests.functional import base


class ServiceEndpoints(base.BaseFunctionalTestCase):
    def test_entrypoints_are_unique(self):
        found_duplicates = defaultdict()
        endpoints = self.ocm.oc.list_endpoints()

        # Group endpoints by service_id and interface type
        def get_sort_keys(e):
            service_type = self.ocm.oc.get_service(e.service_id).type
            return service_type, e.interface, str(e.region_id)

        endpoints = sorted(endpoints, key=get_sort_keys)
        for key, _endpoints in groupby(endpoints, key=get_sort_keys):
            _endpoints = list(_endpoints)

            # And each group should contain 1 endpoint
            if len(_endpoints) > 1:
                found_duplicates[str(key)] = _endpoints

        self.assertFalse(
            found_duplicates,
            f"Found problems in 'openstack endpoint list' \n "
            f"{json.dumps(found_duplicates, indent=4)}",
        )
