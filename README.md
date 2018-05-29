[![build status](https://gitlab.crosscloud.me/CrossCloud/jars/badges/master/build.svg)](https://gitlab.crosscloud.me/CrossCloud/jars/commits/master)
[![coverage report](https://gitlab.crosscloud.me/CrossCloud/jars/badges/master/coverage.svg)](https://gitlab.crosscloud.me/CrossCloud/jars/commits/master)

# [Jars](https://www.youtube.com/watch?v=pjiR2GkXK2Q)
>Good evening and welcome to another edition of 'Storage Jars'. On tonight's programme Mikos Antoniarkis, the Greek rebel leader who seized power in Athens this morning, tells us what he keeps in storage jars. From strife-torn Bolivia, Ronald Rodgers reports on storage jars there. And closer to home, the first dramatic pictures of the mass jail-break near the storage jar factory in Maidenhead. All this and more in 'Storage Jars'!

Jars is a library for communicating with online and offline storages.
Current jars can handle:
- Dropbox
- macOs filesystem
- Windows filesystem
- Google Drive
- OneDrive
- OwnCloud
- Webdav



# installation (current version 1.3.12)
- `pip install --process-dependency-links git+ssh://git@gitlab.crosscloud.me/CrossCloud/jars.git@v1.3.12 --upgrade`


# development
- We use gitlab flow for this project.
- Read [The 11 rules of gitlab flow](https://about.gitlab.com/2016/07/27/the-11-rules-of-gitlab-flow/)


## getting started
- OSX:
    - `git clone git@gitlab.crosscloud.me:crosscloud/jars.git`
    - [install virturalenvwrapper](http://virtualenvwrapper.readthedocs.io/en/latest/index.html)
    - `mkvirtualenv cc-jars --python $(which python3.5) -a . -r requirements.txt`
        - -a: sets the project directory for the virtualenv
        - -r: installs requirements.txt after setup
        - `workon cc-jars` to activate virtualenv and switch to projectdir
        - `cdproject` to switch to project dir when virtualenv is activated
    - `py.test tests` to ensure that everything is setup
    - Sometimes after installing `deactivate` and then `workon cc-jars` is needed.
- Windows:
    - [install chocolatey](https://chocolatey.org/)
    - `choco feature enable -n allowGlobalConfirmation`
    - `choco install git`
    - `choco install pip`
    - `pip install virtualenvwrapper-win`
    - `mkvirtualenv cc-jars`
    - `pip install -r requirements.txt`
    - `py.test tests` to ensure that everything is setup
    - Sometimes after installing `deactivate` and then `workon cc-jars` is needed.


## To use specific version inside the client
- activate the client virtual env
- cd to the jars project
- checkout the branch you are working on.
- run `python setup.py develop`


## Versioning

- Ensure that `bumpversion` is installed (`pip install bumpversion`)
- inspect current version `cat setup.cfg | grep current_version`
- Call `bumpversion` with either
`major`, `minor` or `patch`. This will increase all version numbers and automatically create a commit and tag for the new current version.

- push new version: `git push --tags`
