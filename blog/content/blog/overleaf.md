---
title: "LaTeX for Beginners"
date: "2026-06-22"
description: "Host your own Overleaf instance"
---

## Introduction

A few months ago I started my Master's in Medical Informatics at Heidelberg University and Hochschule Heilbronn. One of the very first assignments is writing a Systematic Review on a given special issue, which we of course write as a group.

<!--more-->

## LaTeX & co.

Almost every scientific paper worth taking seriously is written in LaTeX these days, with a few exceptions[^*]. If you have never touched it: LaTeX is just a language like any other. It defines a set of rules and syntax you follow to get an expected output, in this case a clean `pdf`.

There are two ways to use it. The way it was meant to be used is locally, on your own machine, compiling everything yourself. The other way is through a bloated, partly paywalled web application. And yet that web application, Overleaf, is how most people use it, and honestly for good reason. It gives you real-time collaboration, readable error messages, approachable documentation and a dozen other conveniences. People like to say that *Linux is only free if you do not value your time*, and the same joke applies to hand-rolled, bare-metal, CLI LaTeX versus Overleaf. Overleaf is simply easier.

## What now?

University projects are rarely a solo effort, which means working with people who come from different backgrounds and have different priorities. I come from a Software Engineering background, or really Software Development, so I tend to live in a particular bubble. For context, I daily-drive a MacBook M1 running Linux, made possible by a small team reverse-engineering Apple's drivers in a project that is officially still in alpha[^1]. Most people, very reasonably, just want the most convenient path to a finished document, so we agreed to use Overleaf for our paper.

There is a catch, though. Real-time collaboration on Overleaf requires a paid subscription. Without it everyone has to edit the document one after another instead of at the same time, and that was never going to work for us. Like most student groups, we do the bulk of the work in the last two days before the deadline, all at once, which is exactly when you need several people editing the same file simultaneously. Buying a subscription would have solved this, but it felt unnecessary when there are free alternatives out there. The first one that came to mind was to use Git as our VCS and host the `.tex` files on GitHub.

That adds friction of its own, though. Not everyone works with git day-to-day beyond `add`, `commit` and `push`. (I only recently found out myself that you can rename old commits quite comfortably, among other things.) Git also only really shines when everyone follows the same conventions, and a handful of students writing one paper together is simply a different setting from a team of devs who live in git all day. Neither is better or worse, they are just different contexts.

So, what now? The answer turned out to be wonderfully simple:

Overleaf.

A few days ago I learned that you can self-host the Overleaf Community Edition. It has the same core features as the hosted free version, without the artificial limitations like the cap on concurrent editors and the compile timeouts on larger documents.

## Back to FOSS

Setting up Overleaf CE took me about 20 minutes on a VPS I had lying around. Overleaf ships a simplified wrapper called the [Toolkit](https://docs.overleaf.com/on-premises/configuration/overleaf-toolkit). After setting five or six environment variables, you run a single command, which is really just a bootstrapper for `docker compose`, and your instance is up. If you own a Domain and want to go one step further, a minimal Nginx reverse-proxy config plus one Let's Encrypt command gets you a proper domain with TLS.

That is it. No subscription, no editor limit, no timeouts, and everyone on the team gets the familiar Overleaf interface they already know.

## Final Thoughts

If you ever land in a collaborative team that needs to write LaTeX together and you would rather not go the git route, self-host your own Overleaf instance. It is quick, it is free, and it keeps everyone on comfortable ground.

One last thing: back up whatever you end up hosting. A shared LaTeX project is a lot of collective work, and losing it a few days before the deadline will be no fun for everyone. That is why: always backup.

[^*]: Alternatives: Typst, Word
[^1]: [Asahi Linux: Linux on Apple Silicon, officially still in alpha](https://asahilinux.org/)
