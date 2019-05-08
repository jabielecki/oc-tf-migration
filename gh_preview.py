import argparse
import github3
import migrate
import json
import time

migrate.read_config()
cfg = migrate.cfg

orgs = ['tungstenfabric-preview', 'tungstenfabric-tools-preview', 'tungstenfabric-infra-preview']
gh = github3.login(cfg['github_login'], password=cfg['github_password'])

def create_repo(org, name, dry_run=True):
    print('Creating new repo: {}/{}'.format(org, name), 'DRY_RUN' if dry_run else '')
    if not dry_run:
        org = gh.organization(org)
        for repo in org.repositories():
            if repo.name == name:
                print('Repo', repo.full_name, 'already exists')
                return
        org.create_repository(name)


def create_repos(repos, dry_run=True):
    for repo in repos:
        create_repo(repo.new_org, repo.new_name, dry_run)


def delete_repos(repos=None, dry_run=True):
    if repos is not None:
        full_names = [r.new_full_name() for r in repos]
    for org in orgs:
        print('Searching repos inside org:', org)
        org = gh.organization(org)
        for repo in org.repositories():  # TODO find a way to delete repos without iterating over all repos from org
            if repos is not None:
                if repo.full_name not in full_names:
                    continue
            print('Deleting', repo.full_name, 'DRY_RUN' if dry_run else '')
            if not dry_run:
                repo.delete()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--single-repo", type=str)
    args = parser.parse_args()

    _, _, repos = migrate.extract_reponames(suffix=cfg['org_suffix'])
    if args.single_repo:
        repos = migrate.filter_repos(repos, [args.single_repo])
        print('Repos after filtering:', repos)
    dry_run = args.dry_run
    #repos = repos['gerrit'] + repos['github']
    if args.single_repo:
        delete_repos(repos=repos, dry_run=dry_run)
    else:
        delete_repos(dry_run=dry_run)
    time.sleep(3)
    create_repos(repos, dry_run=dry_run)


if __name__ == '__main__':
    main()
