import argparse
import csv
import sys
import os
import subprocess
import yaml
import pathlib
import pygit2
import jinja2
import shutil
import glob
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

    def old_url(self):
        return 'https://{}/{}/{}'.format(self.old_remote, self.old_org, self.old_name)

    def path(self):
        gitdir = pathlib.Path(cfg['gitdir'])
        old_dir = gitdir / self.old_remote
        repo_path = old_dir / self.old_org / self.old_name
        return str(repo_path)

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
            gerrit = row[4].lower() != 'no'
            remote = cfg['old_hostname']['gerrit'] if gerrit else cfg['old_hostname']['github']
            repo = Repo(old_org, row[1], new_org, row[3], remote)
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
        if os.path.isdir(str(repo_path) + '/.git'):
            exec(['git', '-C', str(repo_path), 'fetch', '--all'])
        else:
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


def get_git_repo(repo):
    path = get_old_repo_path(repo)
    print(path)
    return pygit2.Repository(path)


def branch_in_repo(repo, branch):
    path = get_old_repo_path(repo)
    print(path)
    r = pygit2.Repository(path)
    result = 'refs/remotes/origin/' + branch in r.references
    return result


def squash(repo, branch):
    context = {
        'dco_email': cfg['dco_email'],
        'old_url': repo.old_url()
    }
    write_template('initial-commit-msg.txt.j2', 'initial-commit-msg.txt', context)
    cmd = [os.getcwd() + '/squash.sh', branch, cfg['initial_commit_name'], cfg['initial_commit_email']]
    exec(cmd, get_old_repo_path(repo))


def is_branch_migrated(repo, branch):
    skipped = branch in cfg['skip_branches'].get(repo.old_full_name(), [])
    inrepo = branch_in_repo(repo, branch)
    return inrepo and not skipped


def squash_all(repos, branches):
    for repo in repos:
        for branch in branches:
            if is_branch_migrated(repo, branch):
                squash(repo, branch)
                print('OK:', branch, 'branch found in repo', repo.old_full_name())
            else:
                print('MISSING:', branch, 'branch not found in repo', repo.old_full_name())


def sed_dir(pattern_from, pattern_to, path, whole_repo=False):
    if whole_repo:
        paths = ['*']
    else:
        paths = ['./playbooks/*', './roles/*', './zuul.d/*', './zuul/*', './zuul.yaml', './.zuul.yaml']
    paths_exp = ' -o '.join(['-path "' + p + '"' for p in paths])
    cmd = ['bash', '-c',
           'find . -not -path \'*/\.git*\' -type f \( ' + paths_exp + ' \) -print0 | xargs -0 -r sed -i -s \'s:{}:{}:g\''.format(
               pattern_from, pattern_to)]
    print(cmd)
    exec(cmd, cwd=path)


def generate_replacement_list(all_repos, short_names=False):
    """ short_names: if false, will replace only fqdn and full names (review.opencontrail.org/Juniper/contrail-dev-env and Juniper/contrail-dev-env)
    if true, will replace also short names (contrail-dev-env)"""
    reps, reps_fqdn, reps_short = [], [], []
    for repo in all_repos:
        reps.append((repo.old_full_name(), repo.new_full_name()))
        reps_fqdn.append(
            (repo.old_remote + '/' + repo.old_full_name(), cfg['new_hostname'] + '/' + repo.new_full_name()))
        if repo.old_name != 'contrail':
            reps_short.append((repo.old_name, repo.new_name))
    len_sorter = lambda x: len(x[0])
    sr = sorted(reps_fqdn, key=len_sorter, reverse=True) + sorted(reps, key=len_sorter, reverse=True)
    if short_names:
        sr += sorted(reps_short, key=len_sorter, reverse=True)
    return sr


def patch(repo, branch, repos):
    repo_path = get_old_repo_path(repo)
    cmd = ['git', 'checkout', branch]
    exec(cmd, cwd=repo_path)
    # patches
    patches_path = os.getcwd() + '/patches/{}/{}'.format(repo.old_name, branch)
    print('Patches path:', patches_path)
    if os.path.isdir(patches_path):
        print('Applying patches from:', patches_path)
        for p in glob.glob(patches_path + '/*.patch'):
            print('Applying patch:', p)
            exec(['git', 'apply', p], repo_path)
    # files
    files_path = os.getcwd() + '/files/{}/{}/'.format(repo.old_name, branch)
    print('File replacements path:', files_path)
    if os.path.isdir(files_path):
        print('Replacing files from:', files_path)
        exec(['rsync', '-rv', files_path, repo_path])
    # sed patterns
    full_sed = repo.old_name in cfg['full_sed_repos']
    short_name_sed = repo.old_name in cfg['short_name_sed_repos']
    for from_pattern, to_pattern in generate_replacement_list(repos, short_name_sed):
        sed_dir(from_pattern, to_pattern, repo_path, full_sed)
    # gitreview
    context = {
        'project_name': repo.new_full_name(),
        'branch': branch,
        'gerrit_host': cfg['new_hostname']
    }
    write_template('gitreview.j2', repo.path() + '/.gitreview', context)
    cmd = ['git', 'add', '-A']
    exec(cmd, cwd=repo_path)
    cmd = ['git', 'commit', '--allow-empty', '-F', os.getcwd() + '/patch-commit-msg.txt']
    exec(cmd, cwd=repo_path)






def patch_all(repos, active_branches, all_repos):
    for repo in repos:
        for branch in active_branches:
            if is_branch_migrated(repo, branch):
                patch(repo, branch, all_repos)


def push(repo, branches, dry_run=True):
    path = get_old_repo_path(repo)
    cmd = ['git', 'remote', 'remove', 'new']
    print(cmd)
    try:
        exec(cmd, cwd=path)
    except subprocess.CalledProcessError:
        print('Remote "new" does not exist? Creating:')
    remote_url_base = cfg['remote_url_base']
    remote_url = '{}/{}/{}'.format(remote_url_base, repo.new_org, repo.new_name)
    cmd = ['git', 'remote', 'add', 'new', remote_url]
    print(cmd)
    exec(cmd, cwd=path)
    for branch in branches:
        if is_branch_migrated(repo, branch):
            cmd = ['git', 'push', 'new', branch]
            print(cmd)
            if not dry_run:
                exec(cmd, cwd=path)
            cmd2 = ['git', 'push', 'new', 'refs/replace/*:refs/replace/*']
            print(cmd2)
            if not dry_run:
                exec(cmd2, cwd=path)


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
    all_repos = obj.copy()
    if args.single_repo:
        obj = filter_repos(obj, [args.single_repo])
        print('Repos after filtering:', obj)
    # for r in obj:
    #    print(r.old_full_name())
    # sys.exit(0)
    # 2. Load active branches from Zuul config
    active_branches = get_active_branches()
    print('Active branches:', active_branches)
    # 3. Clone/sync repos
    if cfg['clone']:
        clone_repos(obj, remove=args.full_reclone)
    # 4. Squash history
    squash_all(obj, active_branches)
    # repos_fqdn = [(cfg['old_hostname'] + '/' + r[0], cfg['new_hostname'] + '/' + r[1]) for r in repos]
    # github_repos_fqdn = [('github.com/' + r[0], cfg['new_hostname'] + '/' + r[1]) for r in github_repos]
    # sr = sorted(repos + github_repos + repos_fqdn + github_repos_fqdn, key=lambda x: len(x[0]), reverse=True)
    # 5. Apply patches
    patch_all(obj, active_branches, all_repos)
    # Push
    push_all(obj, active_branches, dry_run=dry_run)


if __name__ == '__main__':
    main()
