import yaml
import sys

to_delete = ['Juniper/contrail-puppet', 'Juniper/contrail-horizon', 'Juniper/contrail-docker', 'Juniper/contrail-server-manager', 'Juniper/puppet-contrail', 'Juniper/contrail-community-docs']

with open(sys.argv[1], 'r') as secrets_file:
    projects = yaml.load(secrets_file)

idx_delete = []

for idx, p in enumerate(projects):
    if 'project' not in p:
        continue
    if p['project']['name'] in to_delete:
        idx_delete.append(idx)

idx_delete.reverse()

for idx in idx_delete:
    del projects[idx]


with open(sys.argv[2], 'w') as out_file:
    yaml.dump(projects, out_file)
