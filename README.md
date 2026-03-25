# L3b4nk4 Writeups

A Hugo-powered personal write-up blog for `L3b4nk4`, built on top of [hugo-theme-reimu](https://github.com/D-Sketon/hugo-theme-reimu).

## Run locally

```bash
git submodule update --init --recursive
hugo server -D
```

## Create a new write-up

```bash
hugo new content post/your-target.md
```

## Main files

- `hugo.toml`: site URL and Hugo settings
- `config/_default/params.yml`: theme branding, menu, colors, and widgets
- `content/post`: write-ups and blog posts
- `content/about.md`: author/about page
- `data/covers.yml`: rotating card covers for posts without a custom `cover`
- `static/avatar` and `static/images`: custom site visuals
