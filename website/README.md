# mcpcap Website

This directory contains the mcpcap project website, deployed to GitHub Pages.

## Structure

- `index.html` - Main landing page
- `styles.css` - Website styling
- `script.js` - Interactive functionality

## Deployment

The website is automatically deployed to GitHub Pages via GitHub Actions when:
- Changes are made to files in the `website/` directory
- Changes are made to `README.md` or `docs/`
- Manual workflow dispatch

## Development

To test the website locally:
1. Open `index.html` in a web browser, or
2. Use a local HTTP server: `python -m http.server 8000`

## Content Updates

The website content should stay in sync with:
- Main README.md
- Documentation in `docs/`
- Available modules and tools

When adding new features, update:
1. Module count in hero stats
2. Module cards section
3. Code examples in quickstart
4. Any relevant feature descriptions

Current shipped modules are `dns`, `dhcp`, `icmp`, `tcp`, and `capinfos`.

The website should not describe startup-time PCAP selection, directory listing, or `--pcap-path` / `--pcap-url` flows. The product starts as:

```bash
mcpcap [--modules MODULES] [--max-packets N]
```

Tool calls then supply the `pcap_file` path or URL.
