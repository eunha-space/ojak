import { defineConfig } from "vitepress";

const repository = "https://github.com/eunha-space/ojak";

export default defineConfig({
  title: "Ojak",
  description: "One ActivityPub core, many runtimes.",
  lang: "en",
  cleanUrls: true,
  lastUpdated: true,
  sitemap: { hostname: "https://ojak.dev" },
  themeConfig: {
    nav: [
      { text: "Introduction", link: "/intro" },
      { text: "Crates", link: "/crates" },
      { text: "Design", link: "/design/" },
      { text: "Showcase", link: "/showcase" },
    ],
    sidebar: [
      {
        text: "Getting started",
        items: [
          { text: "What is Ojak?", link: "/intro" },
          { text: "Crates", link: "/crates" },
          { text: "Showcase", link: "/showcase" },
        ],
      },
      {
        text: "Design records",
        link: "/design/",
        items: [
          { text: "Ojak as a framework", link: "/design/framework" },
          { text: "Serving", link: "/design/serving" },
          { text: "The inbox", link: "/design/inbox" },
          { text: "Portable objects", link: "/design/portable" },
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
