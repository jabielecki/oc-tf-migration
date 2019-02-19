from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import yaml
import base64
import sys
import requests
import subprocess


cfg = {}


def read_yaml(path):
    with open(path, 'r') as yaml_file:
        obj = yaml.load(yaml_file)
        return obj


def read_config():
    new_cfg = read_yaml('./config.yaml')
    cfg.update(new_cfg)


def get_pubkey_zuulv3(project, tenant='', connection_name='gerrit'):
    url = 'http://zuulv3.opencontrail.org/{}/keys/{}/{}.pub'.format(tenant, connection_name, project)
    print('Downloading pubkey from', url)
    req = requests.get(url)
    pem = req.text
    print(pem)
    pubkey = serialization.load_pem_public_key(pem.encode('utf8'), backend=default_backend())
    print(pubkey)
    return pubkey


# from https://github.com/openstack-infra/zuul/blob/master/zuul/lib/encryption.py
def decrypt_pkcs1_oaep(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


def encrypt_pkcs1_oaep(plaintext, public_key):
    """Encrypt data with PKCS#1 (RSAES-OAEP)
    :arg plaintext: A string to encrypt with PKCS#1 (RSAES-OAEP).
    :arg public_key: A public key object as returned by
        :func:generate_rsa_keypair()
    :returns: The encrypted form of the plaintext.
    """
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


# from https://github.com/openstack-infra/zuul/blob/master/zuul/lib/encryption.py
def deserialize_rsa_keypair(data):
    """Deserialize an RSA private key
    This deserializes an RSA private key and returns the keypair
    (private and public) for use in decryption.
    :arg data: A PEM-encoded serialized private key
    :returns: A tuple (private_key, public_key)
    """
    private_key = serialization.load_pem_private_key(
        data,
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return (private_key, public_key)


def decrypt(priv_key, b64_chunks):
    byte_chunks = [base64.b64decode(b64_chunk) for b64_chunk in b64_chunks]
    byte_plaintext = [decrypt_pkcs1_oaep(byte_chunk, priv_key) for byte_chunk in byte_chunks]
    plaintext = ''.join([b.decode('utf8') for b in byte_plaintext])
    return plaintext


def encrypt(pub_key, plaintext):
    bytes_plaintext = plaintext.encode('utf8')
    chunks = []
    return encrypt_pkcs1_oaep(1, pub_key)


def encrypt_tool_old(plaintext, project, url='http://zuulv3.opencontrail.org/', tenant='', connection_name='gerrit'):
    global mode
    p = subprocess.run(['python', 'encrypt_secret.py', url, connection_name, project], stdout=subprocess.PIPE,
        input=plaintext, encoding='utf8', cwd=cfg['zuul_tools_path'])
    out = p.stdout
    lines = out.splitlines()
    y = '\n'.join(lines[10:-1])
    # Return single-element tuple to detect later that it's a reencrypted value,
    # not a string
    return (y,)


def ctor_hof(priv_key, target_project, target_connection):
    """Higher-order function to pass the priv_key variable to the nested
    function"""
    def default_ctor(loader, tag_suffix, node):
        """Reencrypt values tagged with tag encrypted-pkcs-oaep"""
        s = [i.value.replace(' ', '') for i in node.value]
        plain = decrypt(priv_key, s)
        cipher = encrypt_tool_old(plain, target_project, connection_name=target_connection)
        return cipher
    return default_ctor


def render_output_secrets_file(secrets):
    for secret in secrets:
        print('- secret:')
        print('    name:', secret['secret']['name'])
        print('    data:')
        for k, v in secret['secret']['data'].items():
            if type(v) != tuple:
                    print('      ' + k + ": '" + v + "'")
        for k, v in secret['secret']['data'].items():
            if type(v) == tuple:
                print('      ' + k + ': !encrypted/pkcs1-oaep')
                print(v[0])
                pass # render secret
        print()


def main():
    read_config()
    priv_key, pub_key = deserialize_rsa_keypair(open(cfg['recrypt_key_path'], 'rb').read())
    yaml.add_multi_constructor('', ctor_hof(priv_key, cfg['recrypt_target_project'], cfg['recrypt_target_connection']))
    with open(sys.argv[1], 'r') as secrets_file:
        secrets = yaml.load(secrets_file)
    render_output_secrets_file(secrets)


if __name__ == '__main__':
    main()
