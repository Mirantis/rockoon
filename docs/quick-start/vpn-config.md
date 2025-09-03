# Configuring VPN

## SSH tunnel with sshuttle

1. Get IP address of ingress service. On your AIO instance run following command:
```bash
kubectl -n openstack get svc ingress -o jsonpath='{.status.loadBalancer.ingress[].ip}'
```
2. Update local `/etc/hosts` file to point public domain to ingress external IP
```bash
10.172.1.100 aodh.it.just.works barbican.it.just.works cinder.it.just.works cloudformation.it.just.works designate.it.just.works glance.it.just.works gnocchi.it.just.works heat.it.just.works horizon.it.just.works keystone.it.just.works metadata.it.just.works neutron.it.just.works nova.it.just.works novncproxy.it.just.works octavia.it.just.works placement.it.just.works spiceproxy.it.just.works
```
where `10.172.1.100` is the result of previous command execution.
4. Setup `sshuttle` to services external IPs
```bash
sshuttle -r ubuntu@172.16.250.153 10.172.1.0/24
```
where `172.16.250.153` is the public IP of your AIO instance

## OpenVPN (for TryMOSK installation)

By default, the TryMOSK installation process sets up an OpenVPN server on the
instance and creates a client configuration file.

1. Copy OpenVPN client configuration file */src/vpn/client.ovpn* to your
local computer. Use `scp` or another secure file transfer method to download
the file from the instance to your local machine.

2. Update the server IP address in the configuration. In the `client.ovpn` file,
replace the placeholder `<Put your server public IP here>` (found on **line 4**)
with the actual **public IPv4 address** of your AWS instance.
**Example – before:**
```
...
proto udp
remote <Put your server public IP here> 1194
resolv-retry infinite
...
```
**Example – after:**
```
...
proto udp
remote 18.218.29.107 1194
resolv-retry infinite
...
```
Where `18.218.29.107` is the public IPv4 address of your AWS EC2 instance.

3. Use the configuration with an OpenVPN client such as:
    * The official OpenVPN client: [https://openvpn.net/client/](https://openvpn.net/client/)
    * Any compatible VPN client that supports OpenVPN connections

    Refer to your chosen VPN client’s documentation for import and connection instructions.

4. Configur DNS resolver. The OpenVPN server is configured to update the client’s
DNS resolver so that TryMOSK service URLs can be resolved correctly.
    * **macOS and Windows** – OpenVPN clients apply this configuration automatically.
    * **Linux** – Additional DNS configuration may be required, depending on your distribution,
to ensure proper domain resolution for TryMOSK services. Consult your distribution’s
networking documentation for details. You also can update `/etc/hosts` file on your
local computer as is described in step 2 for `sshuttle` setup.
