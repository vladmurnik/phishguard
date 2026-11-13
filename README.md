# PhishGuard

A Chrome extension that warns you at the moment you are about to type a password
into a page that looks like a phishing clone.

Everything happens on your machine: the model is a 748 KB gradient-boosted forest
shipped inside the extension, a score takes 0.04 ms of CPU, and there is not a
single network request in the source.

**Status: work in progress.** The repository is filled in step by step:
features → trainer → engine → extension shell → tests → documentation.

## How it is put together

```text
URL → 30 features → boosted forest → probability → banner above the password field
```

The interesting part is not the model. A URL-only classifier at a 1% false
positive rate recovers only about half of the phishing pages, so asking it about
every page you open would be unbearable. The extension therefore stays silent
until a page is actually ready to receive credentials — a password field appears,
or a form is submitted. That narrows the population of pages by three orders of
magnitude, and that is what makes a mediocre recall good enough.

## Roadmap

- [x] 30 URL features, mirrored in Python and JavaScript
- [x] LightGBM trained on 886k URLs, split grouped by registrable domain
- [x] Forest exported to plain JSON, inference without dependencies or WASM
- [x] Service worker, content script, popup
- [x] Parity gate and behaviour tests
- [ ] Bilingual README with measured results

## License

MIT
