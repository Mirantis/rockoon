========
MASAKARI
========


1. Create a segment related to region:

openstack --os-ha-api-version 1.0 segment create segment1 auto COMPUTE

+-----------------+--------------------------------------+
| Field           | Value                                |
+-----------------+--------------------------------------+
| created_at      | 2021-01-20T15:08:32.000000           |
| updated_at      | None                                 |
| uuid            | 0a1b4f00-b0a3-4721-bc0f-5bda58ddbf41 |
| name            | segment1                             |
| description     | None                                 |
| id              | 3                                    |
| service_type    | COMPUTE                              |
| recovery_method | auto                                 |
+-----------------+--------------------------------------+

2. Add relevant hypervisor to the segment:

openstack hypervisor list
+----+-------------------------------------------------------+-----------------+-------------+-------+
| ID | Hypervisor Hostname                                   | Hypervisor Type | Host IP     | State |
+----+-------------------------------------------------------+-----------------+-------------+-------+
|  3 | oh-ps-6yujav672a23-2-33thlo5acnxy-server-5grbtbjmdcie | QEMU            | 10.10.0.129 | up    |
|  6 | oh-ps-6yujav672a23-0-62uemkkgiat2-server-7jkhb7doyes3 | QEMU            | 10.10.0.161 | up    |
|  9 | oh-ps-6yujav672a23-1-pnra3giy3sav-server-43muyiw7qlzw | QEMU            | 10.10.0.144 | up    |
+----+-------------------------------------------------------+-----------------+-------------+-------+

openstack --os-ha-api-version 1.0 segment host create oh-ps-6yujav672a23-1-pnra3giy3sav-server-43muyiw7qlzw COMPUTE SSH 0a1b4f00-b0a3-4721-bc0f-5bda58ddbf41
+---------------------+-------------------------------------------------------+
| Field               | Value                                                 |
+---------------------+-------------------------------------------------------+
| created_at          | 2021-01-20T15:23:21.000000                            |
| updated_at          | None                                                  |
| uuid                | f22a0136-31fd-40f0-99a2-4336c8aabcd7                  |
| name                | oh-ps-6yujav672a23-1-pnra3giy3sav-server-43muyiw7qlzw |
| type                | COMPUTE                                               |
| control_attributes  | SSH                                                   |
| reserved            | False                                                 |
| on_maintenance      | False                                                 |
| failover_segment_id | 0a1b4f00-b0a3-4721-bc0f-5bda58ddbf41                  |
+---------------------+-------------------------------------------------------+

3. Enable HA mode to a server which is going to be controlled:

openstack server set --property HA_Enabled=True DemoVM

where DemoVM - server (instance) name
