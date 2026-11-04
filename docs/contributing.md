# Building the documentation

The documentation uses Sphinx and MyST to render the repository's Markdown
README. Update `README.md` to change the usage guide; it is included directly
so the two copies stay in sync.

From the repository root, create an environment and build the HTML site:

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r docs/requirements.txt
.venv-docs/bin/python -m sphinx -W --keep-going -b html docs docs/_build/html
```

Open `docs/_build/html/index.html` in a browser to view the site. Warnings fail
the build, matching the checks in CI and on Read the Docs. Building the docs
does not require installing async-hvac or running a Vault server.

## Read the Docs setup

Import `jamaalscarlett/async-hvac` in the Read the Docs dashboard and use
`.readthedocs.yaml` at the repository root as the configuration file. Select
`master` as the default branch. The configuration selects Python, installs
the documentation dependencies, and builds the Sphinx site.

After importing the project, enable pull request builds in its settings if
documentation previews are desired. The repository configuration alone does
not create a hosted project or enable pull request previews.
