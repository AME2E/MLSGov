# Contributing Guidelines

## 1. Issues

We use issues to organize work. Before you start working on a task, create an issue. An issue can be simple, just a quick sentence. Then assign the issue to yourself.

Once you have an issue, create a new branch like `[issue name]-[some words separated by dashes]`, checkout to this branch and start working.

Feel free to push the branch to the origin periodically to save work.

## 2. Pull Requests

Once you are satisfied with your work, open a Pull Request (PR) to merge your issue branch into `main`.

Similar to issue, it is fine to keep the PR simple: a quick sentence as the title and the body can be `Closes #[issue number]` like `Closes #3`. The `Closes #3` part links this PR to the issue and automatically closes the issue when this PR is merged.

PRs need to pass all automated checks and be accepted by a reviewer before being landed.

## Code Style

1. Keep PRs small, less than 300 lines is a good guideline.
2. Document all non-trivial functions, traits, and types.
3. Liberally reference external documents like papers and code with links (mention section or page numbers when linking to a paper.)
4. Describe non-trivial design decisions and how-tos in the in-repo Book.
5. Test all the things, prefer test-driven development where ever possible.
6. Design APIs before implementing them, feel free to open an issue to discuss API design.
7. Write positive and negative tests.

## Pro Moves

1. Can work on many issues in parallel.
2. Can create [`[meta]` issues](https://github.com/dart-lang/sdk/wiki/Working-with-meta-issues) for large tasks.
