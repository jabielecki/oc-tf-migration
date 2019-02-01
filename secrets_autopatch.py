import yaml
import sys

def default_ctor(loader, tag_suffix, node):
     print(loader)
     print(tag_suffix)
     print(node)
     return 'abc'

yaml.add_multi_constructor('', default_ctor)
with open(sys.argv[1], 'r') as secrets_file:
    secrets = yaml.load(secrets_file)

with open(sys.argv[2], 'w') as out_file:
    yaml.dump(secrets, out_file)
