import { defineConfig } from "vitepress";

const repository = "https://github.com/eunha-space/ojak";

export default defineConfig({
  title: "Ojak",
  description: "A bridge between your application and the fediverse.",
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
      message: "Released under the GNU Affero General Public License v3.0.",
    },
  },
});
