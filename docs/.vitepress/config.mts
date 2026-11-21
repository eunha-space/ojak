import { defineConfig } from "vitepress";

const repository = "https://github.com/eunha-space/ojak";
const description = "A bridge between your application and the fediverse.";

export default defineConfig({
  title: "Ojak",
  description,
  // docs/public/og.png is rendered from scripts/og-image.html by
  // `mise run docs:og-image`.
  head: [
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "Ojak" }],
    ["meta", { property: "og:description", content: description }],
    ["meta", { property: "og:image", content: "https://ojak.dev/og.png" }],
    ["meta", { property: "og:image:width", content: "1200" }],
    ["meta", { property: "og:image:height", content: "630" }],
    [
      "meta",
      {
        property: "og:image:alt",
        content: "Ojak: a bridge of birds across the Milky Way, between Altair and Vega.",
      },
    ],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
  ],
  // Each page's own title, which the defaults above leave out.
  transformPageData(page) {
    const title = page.frontmatter.layout === "home" ? "Ojak" : `${page.title} | Ojak`;
    page.frontmatter.head ??= [];
    page.frontmatter.head.push(["meta", { property: "og:title", content: title }]);
  },
  lang: "en",
  cleanUrls: true,
  lastUpdated: true,
  sitemap: { hostname: "https://ojak.dev" },
  themeConfig: {
    nav: [
      { text: "Introduction", link: "/intro" },
      { text: "Getting started", link: "/getting-started" },
      { text: "Tutorial", link: "/tutorial" },
      { text: "Guide", link: "/guide/" },
      { text: "Crates", link: "/crates" },
      { text: "API reference", link: "https://ojak.dev/api/ojak/index.html", target: "_self" },
      { text: "Showcase", link: "/showcase" },
    ],
    sidebar: [
      {
        text: "Introduction",
        items: [
          { text: "What is Ojak?", link: "/intro" },
          { text: "Getting started", link: "/getting-started" },
          { text: "Tutorial: a blog", link: "/tutorial" },
          { text: "Crates", link: "/crates" },
          { text: "Showcase", link: "/showcase" },
        ],
      },
      {
        text: "Guide",
        link: "/guide/",
        items: [
          { text: "Concepts", link: "/guide/concepts" },
          { text: "Serving", link: "/guide/serving" },
          { text: "The inbox", link: "/guide/inbox" },
          { text: "Testing with a temporary inbox", link: "/guide/test-inbox" },
          { text: "Sending and fetching", link: "/guide/sending" },
          { text: "Portable objects", link: "/guide/portable" },
          { text: "Serving many instances", link: "/guide/multitenancy" },
        ],
      },
    ],
    socialLinks: [{ icon: "github", link: repository }],
    editLink: {
      pattern: `${repository}/edit/main/docs/:path`,
    },
    search: { provider: "local" },
    footer: {
      message: "Released under the MIT License.",
    },
  },
});
