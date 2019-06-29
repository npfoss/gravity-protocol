'use strict'

const IPFS = require('ipfs')

/// UTILS
const FILE_TYPES = {
  FILE: 0,
  DIRECTORY: 1,
};
// source: https://github.com/ipfs/js-ipfs/blob/master/examples/browser-mfs/filetree.js
const loadFiles = async function (ipfs, path) {
  const output = {};
  path = path.replace(/\/\/+/g, '/');

  const contents = await ipfs.files.ls(path, {
    long: true,
  })
    .catch(error => console.error(error));

  for (let i = 0; i < contents.length; i++) {
    const entry = contents[i];
    output[entry.name] = entry;

    if (entry.type === FILE_TYPES.DIRECTORY) {
      entry.contents = await loadFiles(ipfs, `${path}/${entry.name}`);
    }
  }

  return output;
};


/// the protocol
class GravityProtocol {
	constructor () {
		const node = new IPFS()

		this.ready = false;

		node.on('ready', () => {
			// Ready to use!
			// See https://github.com/ipfs/js-ipfs#core-api

			this.ready = true;
		})

		this.loadFiles = async function (path) {
			if (!this.ready){
				throw new Error("IPFS node isn't ready yet");
			}
			return loadFiles(node, path)
		}

	}
}



module.exports = GravityProtocol
