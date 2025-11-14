ARG FROM=docker-remote.docker.mirantis.net/ubuntu:noble

FROM $FROM as builder
SHELL ["/bin/bash", "-c"]
ARG TEST_IMAGE
ARG HELM_BINARY="https://binary.mirantis.com/openstack/bin/utils/helm/helm-v3.19.1-linux-amd64"

ENV PIP_BREAK_SYSTEM_PACKAGES=1
# NOTE(pas-ha) need Git for pbr to install from source checkout w/o sdist
ADD https://bootstrap.pypa.io/get-pip.py /tmp/get-pip.py

RUN apt-get update; \
    apt-get -y upgrade

RUN apt-get install -y \
        python3-setuptools \
        build-essential \
        python3-dev \
        libffi-dev \
        libssl-dev \
        libpcre3-dev \
        wget \
        git; \
    python3 /tmp/get-pip.py; \
    pip install wheel; \
    pip install uwsgi

ADD . /opt/operator

RUN set -ex; \
    EXTRA_DEPS=""; \
    if [[ -d /opt/operator/source_requirements ]]; then \
        echo "" > /opt/operator/source-requirements.txt; \
        for req in $(ls -d /opt/operator/source_requirements/*/); do \
            EXTRA_DEPS="${EXTRA_DEPS} $req"; \
            pushd $req; \
                req_name=$(python3 setup.py --name 2>/dev/null |grep -v "Generating ChangeLog"); \
                req_version=$(python3 setup.py --version 2>/dev/null |grep -v "Generating ChangeLog"); \
            popd; \
            echo "$req_name==$req_version" >> /opt/operator/source-requirements.txt; \
        done; \
    else \
        touch /opt/operator/source-requirements.txt; \
    fi; \
    if [[ -n "${EXTRA_DEPS}" ]]; then \
        pip wheel --wheel-dir /opt/wheels --find-links /opt/wheels $EXTRA_DEPS; \
    fi; \
    IMAGE_TAG=$(/opt/operator/tools/get_version.sh); \
    echo "${IMAGE_TAG}" > /opt/operator/image_tag.txt; \
    rm -rf /opt/operator/source_requirements

RUN set -ex; \
    OPENSTACK_CONTROLLER_EXTRAS=""; \
    if [[ "${TEST_IMAGE}" == "True" ]]; then \
        OPENSTACK_CONTROLLER_EXTRAS="[test]"; \
    fi; \
    pip wheel --wheel-dir /opt/wheels --find-links /opt/wheels /opt/operator${OPENSTACK_CONTROLLER_EXTRAS}

RUN wget -q -O /usr/local/bin/helm3 ${HELM_BINARY}; \
    chmod +x /usr/local/bin/helm3

RUN set -ex; \
    for req in $(ls -d /opt/operator/charts/{openstack,infra}/*/); do \
        pushd $req; \
        helm3 dep up; \
        helm3 lint; \
        popd; \
    done

FROM $FROM
SHELL ["/bin/bash", "-c"]
ARG TEST_IMAGE
ARG USER=osctl
ARG UID=42424

COPY --from=builder /tmp/get-pip.py /tmp/get-pip.py
COPY --from=builder /opt/wheels /opt/wheels
COPY --from=builder /opt/operator/uwsgi.ini /opt/operator/uwsgi.ini
COPY --from=builder /opt/operator/source-requirements.txt /opt/operator/source-requirements.txt
COPY --from=builder /opt/operator/image_tag.txt /opt/operator/image_tag.txt
COPY --from=builder /opt/operator/etc/rockoon/ /etc/rockoon/
COPY --from=builder /opt/operator/charts/openstack/ /opt/operator/charts/openstack/
COPY --from=builder /opt/operator/charts/infra/ /opt/operator/charts/infra/
COPY --from=builder /usr/local/bin/helm3 /usr/local/bin/helm3

ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update; \
    apt-get -y upgrade
# FIXME(pas-ha) strace/gdb is installed only temporary for now for debugging
RUN set -ex; \
    apt-get -q update; \
    apt-get install -q -y --no-install-recommends --no-upgrade \
        python3 \
        python3-dbg \
        libpython3.12 \
        libpcre3 \
        net-tools \
        gdb \
        patch \
        strace \
        ca-certificates \
        wget \
        git; \
    python3 /tmp/get-pip.py; \
    pip install --no-index --no-cache --find-links /opt/wheels --pre -r /opt/operator/source-requirements.txt; \
    OPENSTACK_CONTROLLER_PKG=rockoon; \
    if [[ "${TEST_IMAGE}" == "True" ]]; then \
        OPENSTACK_CONTROLLER_PKG=rockoon[test]; \
    fi; \
    pip install --no-index --no-cache --find-links /opt/wheels ${OPENSTACK_CONTROLLER_PKG}; \
    groupadd -g ${UID} ${USER}; \
    useradd -u ${UID} -g ${USER} -m -d /var/lib/${USER} -c "${USER} user" ${USER}

RUN rm -rvf /opt/wheels; \
    apt-get -q clean; \
    rm -rvf /var/lib/apt/lists/*; \
    IMAGE_TAG=$(cat /opt/operator/image_tag.txt); \
    sh -c "echo \"LABELS:\n  IMAGE_TAG: ${IMAGE_TAG}\" > /dockerimage_metadata"
