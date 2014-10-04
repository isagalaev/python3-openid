## 0.1.dev1

First publication of the work in progress. Rough status:

- Directory structure flattened and simplified. It is now close to the final
  state.
- `fetchers`, `discover`, `yadis`, `xrds`, `xri`, `urinorm` are completely
  rewritten. Their respective tests are palatable but need further work.
- `consumer` is the current focus of refactoring, about half way done (which
  makes it an especially ugly mix of two code styles).
- Everything else is mostly untouched.
- `server` is a possible candidate for removal.
