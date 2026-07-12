# Contributing

Contributions are welcomed and encouraged


To give clarity of what is expected of our members, Germ has adopted the
code of conduct defined by the Contributor Covenant. This document is used
across many open source communities, and we think it articulates our values
well. For more, see the [Code of Conduct](./CODE_OF_CONDUCT.md)

## Reporting Bugs

Reporting bugs is a great way for anyone to help improve these libraries.
Please report them using [Github Issues](./issues)
The open source Swift project uses GitHub Issues for tracking bugs.

Because these libraries are under very active development, we receive a lot of bug reports.
Before opening a new issue, take a moment to [browse our existing issues](./issues) to reduce the chance of reporting a duplicate.

## Linting
The repo has a .editorconfig and .swift-format setup. We use both swift
formatter and linter:
```
swift format . -ri && swift format lint . -r
```

## Static Analyzer
We also use the [periphery static analyzer](https://github.com/peripheryapp/periphery) and have a configured `.periphery.yml`


## Changesets
We use [Changesets](https://github.com/changesets/changesets) to document changes and releases.
Please [generate a changeset](https://github.com/changesets/changesets/blob/main/docs/adding-a-changeset.md) for your pull requests.