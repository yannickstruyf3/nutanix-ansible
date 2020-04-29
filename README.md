# Nutanix Ansible Collection

The repo https://github.com/yannickstruyf3/nutanix-ansible contains an Ansible collection (https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for Nutanix. 

The collection is not yet published on Ansible Galaxy. 

**Note**: This repo is **NOT** officially supported by Nutanix. Some API's (for example Karbon) are not yet GA and are still subjected to change.

You can find example playbooks in the `examples` folder. Use the `template_inventory.yml` file as a baseline for configuring your inventory.
Run the steps in the `Installing the collection` section first before trying the examples.

## Module overview
Following modules can be found in the collection:
- ntnx_bucket: Creates, updates, deletes a Nutanix Objects bucket
- ntnx_cluster_dns: Manages the DNS settings for a Nutanix cluster (via Prism Element)
- ntnx_cluster_ntp: Manages the NTP settings for a Nutanix cluster (via Prism Element)
- ntnx_cluster_smtp: Manages the SMTP settings for a Nutanix cluster (via Prism Element)
- ntnx_karbon_cluster: Creates, updates and deletes Nutanix Karbon clusters
- ntnx_karbon_kubeconfig: Retrieves the kubeconfig file for a Nutanix Karbon cluster
- ntnx_karbon_ssh_certificates: Retrieves the public and private SSH certificates for a Nutanix Karbon cluster

## Installing the collection
Perform following steps to use the collection:
```
ansible-galaxy collection build --force --output-path ./pkg
ansible-galaxy collection install ./pkg/yst-ntnx-1.0.0.tar.gz --force
```

## Using the collection
Using the collection in a playbook:
```
---
- hosts: localhost
  collections:
    - yst.ntnx
  tasks:
  - name: Karbon GET kubeconfig
    ntnx_karbon_kubeconfig:
        name: "{{ cluster_name }}"
        state: present
        pc_host: "{{ pc_host }}"
        pc_username: "{{ pc_username }}"
        pc_password: "{{ pc_password }}"
        kubeconfig_download_path: "./my-kubeconfig"
        ssl_verify: False
```

## Reporting issues and requests
Issues and feature requests can be reported via this URL: https://github.com/yannickstruyf3/nutanix-ansible/issues.
Issues and feature requests will be handled on a best-effort basis.