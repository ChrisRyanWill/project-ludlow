> **DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE**

# How your data is protected

## What this site cannot see
When you sign a card, your name, email, phone number and the card itself are locked with a key that is created on your phone. That key is then split among your trustees so that no single trustee, and not this website, can open it. Only a set number of trustees together (for example 3 of 5) can open cards, and they do it on their own device.

The campaign's union name and employer name are encrypted too. The secrets that unlock them travel in the part of a link after the "#", which your browser never sends to a server.

## What this site can see
- That a campaign exists, how many cards it has, and when they were signed.
- The trustees' public keys (which cannot open anything).
- The internet address (IP) of your request, briefly, to limit abuse. It is never written to disk or to logs.

## The honest limits
- **The confirmation email.** The law needs a confirmation to be sent to each signer. At that moment the server briefly handles your email address and card details to send the message, and then discards them. Your email provider keeps its own delivery records.
- **Your hosting provider** may keep network logs that include IP addresses.
- **Screens and phones.** Anyone who can see or use your phone can see what you are doing. Use a personal device on mobile data.
- **A member who is secretly hostile** can see the card count.
- **Trustees acting together** can open cards at any time, even before you reach a majority. The software warns them; it cannot stop them.
- **The website's code** is delivered by the server. A hacked server could send bad code. That is why the code is open source and why you can check its fingerprint on the "Verify this software" page.
- **After you go public**, names are no longer secret. The encryption protects the organizing period, not afterward.

## After the union goes public (the workspace)
A union that has gone public must know who its members are. The workspace stores names, emails, phone numbers and addresses encrypted at rest. Officers can see the roster, and every look at your record is logged where you can see it. Grievances and private notes are end-to-end encrypted so only the people assigned can read them. Secret ballots have no link between a voter and a ballot. The money ledger is a tamper-evident chain that every member's browser can verify.
The server can read at-rest fields (it must, to send mail and print notices). Someone who stole both the database and the server's master key could read them.

TODO(lawyer): review this page and the Terms before real-world use.
