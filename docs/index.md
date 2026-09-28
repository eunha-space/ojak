---
layout: home

hero:
  name: Ojak
  text: One ActivityPub core, many runtimes.
  tagline: >-
    A Rust framework for ActivityPub applications, named for Ojakgyo
    (오작교, 烏鵲橋), the bridge of crows and magpies across the Milky Way.
  actions:
    - theme: brand
      text: What is Ojak?
      link: /intro
    - theme: alt
      text: Design records
      link: /design/
    - theme: alt
      text: GitHub
      link: https://github.com/eunha-space/ojak

features:
  - title: The application owns its data
    details: >-
      Ojak never holds a follower, a post or an account of its own.  It asks
      the application, and does the protocol around what it is told.
  - title: A portable core
    details: >-
      Protocol decisions live in crates with no I/O.  Runtimes supply
      networking, storage, clocks and scheduling for their platform.
  - title: JSON-LD read by meaning
    details: >-
      Documents are read by what their keys stand for, over contexts Ojak
      ships instead of fetches, and written back in one spelling.
  - title: Portable objects
    details: >-
      Objects whose identity is a key rather than a hostname (FEP-ef61), signed
      with a key that need not live on the server.
---

