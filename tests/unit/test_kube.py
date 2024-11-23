from unittest import mock

import pykube

from rockoon import kube


def test_get_kubernetes_objects():
    kube_objects = kube.get_kubernetes_objects()
    assert kube_objects[("v1", "Secret")] == kube.Secret
    assert kube_objects[("v1", "Namespace")] == pykube.objects.Namespace


def test_bare_pod_vs_job_child():
    """Test that bare pods are not failing job_child status check"""

    o = dict(metadata={"name": "spam", "namespace": "ham"})
    p = kube.Pod(api=mock.Mock(), obj=o)
    assert p.job_child is False, "bare Pod is a job child"
