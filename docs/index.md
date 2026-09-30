---
layout: home

hero:
  name: Ojak
  text: A bridge between your application and the fediverse.
  tagline: >-
    A Rust framework for ActivityPub applications, named for Ojakgyo
    (오작교, 烏鵲橋), the bridge of crows and magpies across the Milky Way.
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: What is Ojak?
      link: /intro
    - theme: alt
      text: Guide
      link: /guide/
    - theme: alt
      text: Showcase
      link: /showcase
    - theme: alt
      text: GitHub
      link: https://github.com/eunha-space/ojak

features:
  - title: Your application owns its data
    details: >-
      Ojak never holds a follower, a post or an account of its own.  It asks
      your application, and does the protocol around what it is told.
    link: /guide/concepts
    linkText: Concepts
  - title: Strict about who said what
    details: >-
      Every activity is authenticated by an HTTP signature or an FEP-8b32
      proof before your code sees it, and nothing embedded is trusted that
      its sender cannot vouch for.
    link: /guide/inbox
    linkText: The inbox
  - title: JSON-LD read by meaning
    details: >-
      Documents are read by what their keys stand for, not how they are
      spelled, over contexts Ojak ships instead of fetching.
    link: /guide/concepts#documents-are-read-by-meaning
    linkText: Reading documents
  - title: Portable objects
    details: >-
      Objects whose identity is a key rather than a hostname (FEP-ef61), signed
      with a key that need not live on the server.
    link: /guide/portable
    linkText: Portable objects
---

