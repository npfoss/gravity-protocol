Note: all the peering servers have stopped running, so this no longer works unless you run your own.
It's currently unmaintained, but still interesting.
A new iteration of similar ideas is [Dynamic ID](https://dynamicid.org), which is actively under development.


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

## Beware

This software is still in alpha, and as we all know, software is made of bugs.
(If you find one, please open an [issue](https://github.com/npfoss/gravity-protocol/issues)!)

Breaking changes to the protocol/interface will occur,
but we will always provide a mitigation path to avoid losing any user data.

This protocol has not undergone an independent professional security audit.
We think it's secure, but I'd avoid using it for anything illegal.

## Install

`npm install --save gravity-protocol`

Or to build from source, clone the repo then `npm install` in the root directory.

## Usage

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

### IPFS

Gravity relies very heavily upon [IPFS](https://ipfs.io) and [libp2p](https://libp2p.io/),
together an ambitious open source project to re-decentralize the internet,
and one for which we are very grateful.
