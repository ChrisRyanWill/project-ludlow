> **DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE**

# How your data is protected

## What this site cannot see
When you sign a card, your name, email, phone number and the card itself are locked with a key that is created on your phone. That key is then split among your trustees so that, once every trustee has joined and the founder has confirmed the committee, no single trustee, and not this website, can open it. Only a set number of trustees together (for example 3 of 5) can open cards, and they do it on their own device. Until the founder has confirmed the whole committee, cards are locked to the founder alone.

Your invitation link carries a check of the founder's key (in the part after the "#", which your browser never sends to a server). Your phone compares it with the keys this website hands out, and refuses to sign if they do not match, so a website that tried to give your phone keys of its own would be caught.

The campaign's union name and employer name are encrypted too. The secrets that unlock them travel in the part of a link after the "#", which your browser never sends to a server.

## What this site can see
- That a campaign exists, how many cards it has, when they were signed and whether they have been counted, how many trustees it has and its release number.
- Which invitation link each card came from, and which card made each link. That shows who invited whom, though not anyone's name.
- When a confirmation email was sent, and the email provider's id for that message. Together with the email provider's own records, that id could identify who signed.
- The trustees' public keys, and the committee list the founder signed (neither can open anything).
- The internet address (IP) of your request, briefly, to limit abuse. It is never written to disk or to logs.

## The honest limits
- **The confirmation email.** The law needs a confirmation to be sent to each signer. At that moment the server briefly handles your email address and card details to send the message, and then discards them. Your email provider keeps its own delivery records.
- **Your hosting provider** may keep network logs that include IP addresses.
- **Screens and phones.** Anyone who can see or use your phone can see what you are doing. Use a personal device on mobile data.
- **A member who is secretly hostile** can see the card count, and, because anyone who has joined can invite people, could try to raise it.
- **The release number.** Each campaign sets a number when it starts, and the server will not hand the sealed cards to the trustees until that many people have signed and been counted. It is a safety catch, not proof that that many real people signed, and it only holds the trustees back if they do not also run the server.
- **The founder, and whoever gave you your link.** Your card's protection starts with the founder's key, so you are trusting the founder, and the person who sent you the link, to be who they seem. The signing page shows the founder's key words: ask the founder to read theirs to you if you want to be sure.
- **The website's code** is delivered by the server. A hacked server could send bad code, and the key check above would not help against that. That is why the code is open source and why you can check its fingerprint on the "Verify this software" page. That check catches mistakes and casual tampering, not a server determined to cheat; the strongest check is to compare with a copy that someone you trust built themselves.
- **After you go public**, names are no longer secret. The encryption protects the organizing period, not afterward.

## After the union goes public (the workspace)
A union that has gone public must know who its members are. The workspace stores names, emails, phone numbers and addresses encrypted at rest. Officers can see the roster, and every look at your contact details is logged where you can see it (your name also appears in other places, such as roles and cases, without a log entry). Grievances and private notes are end-to-end encrypted so only you, every chief steward, and any steward the case is shared with can read them. (The keys they are locked to come from the website, and the check that protects cards is not built for them yet, so a website that lied about those keys could read new ones.) Secret ballots are stored without your name or the time you voted, and any member can recount the published ballots. (A website that had been secretly altered could still note which session sent which ballot.) The money ledger is a tamper-evident chain that every member's browser checks and remembers.
The server can read at-rest fields (it must, to send mail and print notices). Someone who stole both the database and the server's master key could read them.

TODO(lawyer): review this page and the Terms before real-world use.
