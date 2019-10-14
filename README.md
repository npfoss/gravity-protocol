# Gravity

Gravity is an open and decentralized private social network.

Why does it have to be decentralized?
- 3 second answer: competition.
- 3 minute answer: [The Case for a Decentralized Social Network](https://medium.com/npfoss/the-case-for-a-decentralized-social-network-2683b727abf5)

Do we really need yet another social network?
Surely this space is over-saturated...
- Short answer: We looked really hard but couldn't find anything that was private, didn't rely on *any* third parties, and was more than just a messenger.
- Long answer: Check out our [extensive survey](https://medium.com/npfoss/so-you-want-to-leave-facebook-1ab3603f164a) which resulted from that research.

This repo is a sample implementation of the protocol underlying the Gravity social network.
Since it's open and decentralized, anyone can participate;
you don't need to go through [gravitynet.io](https://www.gravitynet.io/) or even use this code to do so.

# Beware

This software is still in alpha, and as we all know, software is made of bugs.
(If you find one, please open an [issue](https://github.com/npfoss/gravity-protocol/issues)!)

Breaking changes to the protocol/interface will occur,
but we will always provide a mitigation path to avoid losing any user data.

This protocol has not undergone an independent professional security audit.
We think it's secure, but I'd avoid using it for anything illegal.

# Install

`npm install --save gravity-protocol`

Or to build from source, clone the repo then `npm install` in the root directory.

# Usage

```js
const GravityProtocol = require('gravity-protocol');
const gp = new GravityProtocol();
gp.ready.then(() => {
	const myIdentity = {id: gp.getIpnsId(), publicKey: gp.getPublicKey()};
	console.log(myIdentity);
});
```

For a real example of the protocol in use and interacting with the rest of the network,
see [gravity-minimal](https://github.com/npfoss/gravity-minimal).

# Contribute

Contributions are welcome!
Feel free to open PRs, just make sure to always lint with `npm run lint-fix` please.

# Contact

Drop us a line at [hello@gravitynet.io](mailto:hello@gravitynet.io)!
We accept...
- ...feedback of any kind
- ...bug reports (although those are best as [issues](https://github.com/npfoss/gravity-protocol/issues))
- ...suspected security vulnerabilities
- ...musings on the future of the internet, connectivity, and human interaction
- ...anything really, we're always happy to hear from our users

# Acknowledgments

- original idea was [Nate Foss](https://github.com/npfoss)
- initial system design was Nate Foss, Matthew Pfeiffer, Kifle Woldu, and Arthur Williams
as our [final project](https://courses.csail.mit.edu/6.857/2019/project/17-Foss-Pfeiffer-Woldu-Williams.pdf) for MIT's 6.857
- contributors:
[Nate Foss](https://github.com/npfoss), [Jeff Liu](https://github.com/jeffliu6)

## IPFS

Gravity relies very heavily upon [IPFS](https://ipfs.io) and [libp2p](https://libp2p.io/),
together an ambitious open source project to re-decentralize the internet,
and one for which we are very grateful.
