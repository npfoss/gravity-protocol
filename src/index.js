// for eslint:
/* global atob btoa */

const IPFS = require('ipfs');
const Cookies = require('js-cookie');
const sodium = require('libsodium-wrappers');


//*  UTILS
const FILE_TYPES = {
  FILE: 0,
  DIRECTORY: 1,
};
// source: https://github.com/ipfs/js-ipfs/blob/master/examples/browser-mfs/filetree.js
const loadDirs = async function (ipfs, path) {
  const output = {};
  const cleanpath = path.replace(/\/\/+/g, '/');

  const contents = await ipfs.files.ls(cleanpath, {
    long: true,
  })
    .catch(error => console.error(error));

  for (let i = 0; i < contents.length; i += 1) {
    const entry = contents[i];
    output[entry.name] = entry;

    if (entry.type === FILE_TYPES.DIRECTORY) {
      entry.contents = await loadDirs(ipfs, `${cleanpath}/${entry.name}`);
    }
  }

  return output;
};


//*  the protocol
class GravityProtocol {
  constructor() {
    let ipfsReady = false;
    let sodiumReady = false;
    this.ready = () => ipfsReady && sodiumReady;

    const node = new IPFS();
    node.on('ready', () => {
      // Ready to use!
      // See https://github.com/ipfs/js-ipfs#core-api

      ipfsReady = true;
    });

    (async function awaitSodiumReady() {
      await sodium.ready;
      sodiumReady = true;
    }());

    this.loadDirs = async (path) => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      return loadDirs(node, path);
    };

    // use with caution
    this.setMasterKey = (newkey) => {
      Cookies.set('gravity-master-key', newkey);// , { secure: true });
      // TODO: store somewhere better than in a cookie.
      //  (only store a device key, keep master key enc in profile only)
    };

    // use with caution
    this.resetMasterKey = () => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      const key = sodium.crypto_secretbox_keygen();
      this.setMasterKey(btoa(String.fromCharCode.apply(null, key)));
    };

    this.getMasterKey = () => {
      const cookie = Cookies.get('gravity-master-key');
      if (cookie === undefined) {
        throw new Error('No master key');
      }
      return Uint8Array.from(atob(cookie), c => c.charCodeAt(0));
    };
  }
}


module.exports = GravityProtocol;
