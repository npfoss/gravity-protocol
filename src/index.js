'use strict'

const IPFS = require('ipfs')


class GravityProtocol {
	constructor () {

		const node = new IPFS()

		this.ready = false;

		node.on('ready', () => {
			// Ready to use!
			// See https://github.com/ipfs/js-ipfs#core-api

			this.ready = true;
		})

		

	}
}



module.exports = GravityProtocol
