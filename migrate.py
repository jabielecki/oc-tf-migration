import argparse
import csv
import os
import subprocess
import yaml
import pathlib
import pygit2
import jinja2
import shutil
from jinja2 import Template


cfg = {}
extra_env = {'GIT_SSH_COMMAND': 'ssh -i {}/id_rsa -o IdentitiesOnly=yes'.format(os.getcwd())}


def read_yaml(path):
    with open(path, 'r') as yaml_file:
        obj = yaml.load(yaml_file)
        return obj


def render_template(tpl_path, context):
    with open(tpl_path, 'r') as tpl_file:
        tpl = tpl_file.read()
    template = Template(tpl)
    out = template.render(context)
    return out


def write_template(tpl_path, dest_path, context):
    out = render_template(tpl_path, context)
    with open(dest_path, 'w') as dest_file:
        dest_file.write(out)


def read_config():
    new_cfg = read_yaml('./config.yaml')
    cfg.update(new_cfg)


def exec(cmd, cwd='.', extra_env=extra_env):
    environment = os.environ.copy()
    environment.update(extra_env)
    print('executing:', cmd, 'in:', cwd, 'extra env:', extra_env)
    subprocess.check_call(cmd, cwd=cwd, env=environment)


def get_active_branches():
    branches = set()
    pipelines = read_yaml(cfg['pipelines_file_path'])
    for pipeline in pipelines:
        p = pipeline['pipeline']
        if p.get('name', None) in ['check', 'gate']:
            for event in p['trigger'].get('gerrit', []):
                for branch in event.get('branch', []):
                    branches.add(branch[1:-1])
    return list(branches)


class Repo():

    def __init__(self, old_org, old_name, new_org, new_name, old_remote='github.com'):
        self.old_org = old_org
        self.old_name = old_name
        self.new_org = new_org
        self.new_name = new_name
        self.old_remote = old_remote

    def new_full_name(self):
        return '{}/{}'.format(self.new_org, self.new_name)

    def old_full_name(self):
        return '{}/{}'.format(self.old_org, self.old_name)

    def __str__(self):
        return 'old: {}, new: {}'.format(self.old_full_name(), self.new_full_name())

    def __repr__(self):
        return 'Repo<' + self.__str__() + '>'


def extract_reponames(suffix=''):
    fname = cfg['repos_csv_file_path']
    repos = []
    obj = []
    github_repos = []
    with open(fname) as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        next(reader)
        for row in reader:
            old_org = row[0]
            new_org = row[2] + suffix
            repo = Repo(old_org, row[1], new_org, row[3])
            old = '{}/{}'.format(old_org, row[1])
            new = '{}/{}'.format(new_org, row[3])
            if row[4].lower() == 'no':
                github_repos.append((old, new))
            else:
                repos.append((old, new))
            obj.append(repo)
    return repos, github_repos, obj


def filter_repos(repos, old_short_names):
    return [r for r in repos if r.old_name in old_short_names]


def clone_repos(repos, remove=False):
    for repo in repos:
        old_dir = cfg['gitdir'] + '/' + repo.old_remote
        os.makedirs(old_dir, exist_ok=True)
        old_url = 'https://' + repo.old_remote
        repo_path = get_old_repo_path(repo)
        repo_path = pathlib.Path(repo_path)
        os.makedirs(str(repo_path.parent), exist_ok=True)
        if remove:
            print('Removing repo dir:', str(repo_path))
            try:
                shutil.rmtree(str(repo_path))
            except FileNotFoundError:
                pass
        try:
            exec(['git', '-C', str(repo_path), 'fetch', '--all'])
            exec(['git', '-C', str(repo_path), 'pull'])
        except subprocess.CalledProcessError:
            exec(['git', 'clone', old_url + '/' + repo.old_full_name(), repo.old_full_name()], old_dir)


def get_old_repo_path_(repo):
    gitdir = pathlib.Path(cfg['gitdir'])
    old = cfg['old_hostname']
    old_dir = gitdir / old
    repo_path = old_dir / repo
    return str(repo_path)


def get_old_repo_path(repo):
    gitdir = pathlib.Path(cfg['gitdir'])
    old_dir = gitdir / repo.old_remote
    repo_path = old_dir / repo.old_org / repo.old_name
    return str(repo_path)


def branch_in_repo(repo, branch):
    path = get_old_repo_path(repo)
    print(path)
    r = pygit2.Repository(path)
    refs = list(r.references)
    result = 'refs/remotes/origin/' + branch in r.references
    return result


def squash(repo, branch):
    cmd = [os.getcwd() + '/squash.sh', branch]
    exec(cmd, get_old_repo_path(repo))


def is_branch_migrated(repo, branch):
    skipped = branch in cfg['skip_branches'].get(repo, [])
    inrepo = branch_in_repo(repo, branch)
    return inrepo and not skipped


def squash_all(repos, branches):
    for repo in repos:
        for branch in branches:
            if is_branch_migrated(repo, branch):
                squash(repo, branch)
            else:
                print('branch', branch, 'not in repo', repo.old_full_name())


def sed_dir(pattern_from, pattern_to, path):
    cmd = ['bash', '-c', 'find . -not -path \'*/\.git*\' -type f -print0 | xargs -0 -n1 sed -i -s \'s:{}:{}:g\''.format(pattern_from, pattern_to)]
    print(cmd)
    exec(cmd, cwd=path)


def patch(repo, branch, repos):
    repo_path = get_old_repo_path_(repo)
    patch_path = os.getcwd() + '/patches/' + repo.split('/')[-1] + '.patch'
    print(patch_path)
    if os.path.exists(patch_path):
        print('Applying patch:', patch_path)
        exec(['git', 'apply', patch_path], repo_path)
    for old, new in repos:
        sed_dir(old, new, repo_path)
    cmd = ['git', 'add', '-A']
    exec(cmd, cwd=repo_path)
    cmd = ['git', 'commit', '-m', '.']
    exec(cmd, cwd=repo_path)


def push(repo, branches, dry_run=True):
    remote_url_base = 'ssh://git@github.com'
    remote_url = '{}/{}/{}'.format(remote_url_base, repo.new_org, repo.new_name)
    path = get_old_repo_path(repo)
    cmd = ['git', 'remote', 'add', 'new', remote_url]
    print(cmd)
    if not dry_run:
        try:
            exec(cmd, cwd=path)
        except subprocess.CalledProcessError:
            print('Remote already exists?')
    for branch in branches:
        if is_branch_migrated(repo, branch):
            cmd = ['git', 'push', 'new', branch]
            print(cmd)
            if not dry_run:
                exec(cmd, cwd=path)


def push_all(repos, branches, dry_run=True):
    for repo in repos:
        push(repo, branches, dry_run)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--full-reclone", action="store_true")
    parser.add_argument("--single-repo", type=str)
    args = parser.parse_args()
    dry_run = args.dry_run
    read_config()
    # 1. Load repos list
    repos, github_repos, obj = extract_reponames(suffix=cfg['org_suffix'])
    if args.single_repo:
        obj = filter_repos(obj, [args.single_repo])
        print('Repos after filtering:', obj)
    # 2. Load active branches from Zuul config
    active_branches = get_active_branches()
    print('Active branches:', active_branches)
    # 3. Clone/sync repos
    if cfg['clone']:
        clone_repos(obj, remove=args.full_reclone)
    # 4. Squash history
    squash_all(obj, active_branches)
    repos_fqdn = [(cfg['old_hostname'] + '/' + r[0], cfg['new_hostname'] + '/' + r[1]) for r in repos]
    github_repos_fqdn = [('github.com/' + r[0], cfg['new_hostname'] + '/' + r[1]) for r in github_repos]
    sr = sorted(repos + github_repos + repos_fqdn + github_repos_fqdn, key=lambda x: len(x[0]), reverse=True)
    # 5. Apply patches
    patch('Juniper/contrail-project-config', 'master', sr)
    # Push
    push_all(obj, active_branches, dry_run=dry_run)


if __name__ == '__main__':
    main()
