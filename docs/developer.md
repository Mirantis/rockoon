# Developer Guide

## Code Style

Rockoon Contoller uses [Black](https://black.readthedocs.io/en/stable/) code formatter
To check your chenages and format them use
```bash
tox -e black
```

## Tests

Each commit should require to pass code styles and unittests. To run unittests locally
```bash
tox -e py310
```

## Running controller locally

Rockoon Controller is deployed as helm chart into kubernetes cluster. However there is
possibility to run controller locally. For this:
```bash
tox -e dev
```
