# Access OpenStack

This section explains how to access your OpenStack environment as admin user.
Before you proceed, make sure that you can access the Kubernetes API.

## Built-in admin CLI

You can use the built-in admin CLI client and execute the openstack commands from
a dedicated pod deployed in the `openstack` namespace:

```bash
kubectl -n openstack exec -it deployment/keystone-client -- bash
```

This pod has `python-openstackclient` and all required plugins already installed.
The `python-openstackclient` command-line client is configured to use the admin user
credentials. To view the detailed configuration for the OpenStack run the command
in the pod:

```bash
cat /etc/openstack/clouds.yaml
```

## Horizon

Before you proceed, make sure that you can access to Horizon URL from your workplace.
In case of AIO installation you can use VPN according to [this article](../../quick-start/vpn-config.md).

1. Obtain the admin user credentials from the `openstack-identity-credentials` secret
in the `openstack-external` namespace:
```bash
kubectl -n openstack-external get secrets openstack-identity-credentials -o jsonpath='{.data.clouds\.yaml}' | base64 -d
```
Example of a system response:
```yaml
clouds:
  admin:
    auth:
      auth_url: https://keystone.it.just.works/
      password: <ADMIN_PWD>
      project_domain_name: <ADMIN_PROJECT_DOMAIN>
      project_name: <ADMIN_PROJECT>
      user_domain_name: <ADMIN_USER_DOMAIN>
      username: <ADMIN_USER_NAME>
    endpoint_type: public
    identity_api_version: 3
    interface: public
    region_name: CustomRegion
  admin-system:
    auth:
      auth_url: https://keystone.it.just.works/
      password: <ADMIN_PWD>
      system_scope: all
      user_domain_name: <ADMIN_USER_DOMAIN>
      username: <ADMIN_USER_NAME>
    endpoint_type: public
    identity_api_version: 3
    interface: public
    region_name: CustomRegion
```
2. Access Horizon through your browser using its public service. By default for Rockoon AIO
installation it's [**https://horizon.it.just.works**](https://horizon.it.just.works).
To log in, specify the user name and domain name obtained in previous step from the
`<ADMIN_USER_NAME>`, `<ADMIN_PWD>` and `<ADMIN_USER_DOMAIN>` values.

> If OpenStack was deployed with self-signed TLS certificates for public endpoints,
> you may get a warning about an untrusted certificate. To proceed, allow the connection.

## CLI from your local machine

To be able to access your OpenStack environment through the CLI, you need to configure the
openstack client environment using either an `openstackrc` environment file or `clouds.yaml`
file.

* **openstackrc**
    1. Log in to Horizon as described in previous chapter
    2. Download the `openstackrc` file from the web UI.
    3. On any shell from which you want to run OpenStack commands, source the environment
       file for the respective project.
* **clouds.yaml**
    1. Obtain clouds.yaml:
```bash
mkdir -p ~/.config/openstack
kubectl -n openstack-external get secrets openstack-identity-credentials -o jsonpath='{.data.clouds\.yaml}' | base64 -d > ~/.config/openstack/clouds.yaml
```
      The OpenStack client looks for `clouds.yaml` in the following locations:
        * current directory
        * ~/.config/openstack
        * /etc/openstack.

    2. Export the OS_CLOUD environment variable:
```bash
export OS_CLOUD=admin
```

Now, you can use the openstack CLI as usual. For example:
```bash
openstack user list
```
Example of an expected system response:
```bash
+----------------------------------+-----------------+
| ID                               | Name            |
+----------------------------------+-----------------+
| dc23d2d5ee3a4b8fae322e1299f7b3e6 | internal_cinder |
| 8d11133d6ef54349bd014681e2b56c7b | admin           |
+----------------------------------+-----------------+
```
> If OpenStack was deployed with self-signed TLS certificates for public endpoints,
> you may need to use the openstack command-line client with certificate validation disabled.
> For example:
```bash
openstack --insecure user list
```
