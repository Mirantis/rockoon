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


@mock.patch("rockoon.kube.Job.wait_ready")
@mock.patch("rockoon.kube.Job.create")
def test_cron_job_run_wait_completion(
    mock_job_create, mock_wait_ready, cronjob
):
    """Test kube CronJob run() with wait for completion"""
    cronjob_obj = kube.CronJob(kube.kube_client(), cronjob)

    cronjob_obj.run(wait_completion=True, timeout=5, delay=1)
    mock_job_create.assert_called_once()
    mock_wait_ready.assert_called_once()


@mock.patch("rockoon.kube.Job.wait_ready")
@mock.patch("rockoon.kube.Job.create")
def test_cron_job_run_no_wait_completion(
    mock_job_create, mock_wait_ready, cronjob
):
    """Test kube CronJob run() without wait for completion"""
    cronjob_obj = kube.CronJob(kube.kube_client(), cronjob)

    cronjob_obj.run(wait_completion=False)
    mock_job_create.assert_called_once()
    mock_wait_ready.assert_not_called()


@mock.patch("rockoon.kube.time.sleep")
@mock.patch("rockoon.kube.CronJob.reload")
def test_cron_job_suspend_wait_completion(mock_reload, mock_sleep, cronjob):
    """Test kube CronJob suspend() with wait for completion"""
    cronjob_obj = kube.CronJob(kube.kube_client(), cronjob)
    cronjob_obj.service = mock.Mock()
    cronjob_obj.helmbundle_ext = kube.HelmBundleExt(
        chart="nova", manifest="cron-job", images=[]
    )

    def reload_side_effect():
        if mock_reload.call_count >= 2:
            cronjob_obj.obj["spec"]["suspend"] = True

    mock_reload.side_effect = reload_side_effect

    cronjob_obj.suspend(wait_completion=True, timeout=5, delay=1)
    cronjob_obj.service.set_release_values.assert_called_with(
        "nova", {"conf": {"cronjob": {"suspend": True}}}
    )
    mock_sleep.assert_called_once_with(1)


@mock.patch("rockoon.kube.time.sleep")
@mock.patch("rockoon.kube.CronJob.reload")
def test_cron_job_suspend_no_wait_completion(mock_reload, mock_sleep, cronjob):
    """Test kube CronJob suspend() without wait for completion"""
    cronjob_obj = kube.CronJob(kube.kube_client(), cronjob)
    cronjob_obj.service = mock.Mock()
    cronjob_obj.helmbundle_ext = kube.HelmBundleExt(
        chart="nova", manifest="cron-job", images=[]
    )

    cronjob_obj.suspend(wait_completion=False)
    cronjob_obj.service.set_release_values.assert_called_with(
        "nova", {"conf": {"cronjob": {"suspend": True}}}
    )
    mock_sleep.assert_not_called()
