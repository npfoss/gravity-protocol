
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
  });
  // .catch(error => console.error(error));

  for (let i = 0; i < contents.length; i += 1) {
    const entry = contents[i];
    output[entry.name] = entry;

    if (entry.type === FILE_TYPES.DIRECTORY) {
      entry.contents = await loadDirs(ipfs, `${cleanpath}/${entry.name}`);
    }
  }

  return output;
};

// concatenates two Uint8Array objects
const uintConcat = (a, b) => {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
};

// sleep nonblocking
const sleep = ms => new Promise(r => setTimeout(r, ms));

// for base64 string conversion to/from url safe strings (for pubkeys)
const toURL64replacements = { '+': '.', '/': '_', '=': '-' };
const fromURL64replacements = { '.': '+', '_': '/', '-': '=' };
const base64toURL = s => {
  return s.replace(/[+/=]+/g, c => toURL64replacements[c])
}
const URLtoBase64 = s => {
  return s.replace(/[._-]+/g, c => fromURL64replacements[c])
}


//*  the protocol
class GravityProtocol {
  constructor() {
    let ipfsReady = false;
    let sodiumReady = false;
    this.ready = () => ipfsReady && sodiumReady;
    this.readyAsync = async () => {
      await sodium.ready;
      while (!ipfsReady) {
        await sleep(400)
      }
      return true;
    }

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
      Cookies.set('gravity-master-key', newkey);// , { secure: true }); // for https only
      // TODO: store somewhere better than in a cookie.
      //  (only store a device key, keep master key enc in profile only)
    };

    // use with caution
    this.resetMasterKey = () => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      const key = sodium.crypto_secretbox_keygen();
      this.setMasterKey(sodium.to_base64(key));
    };

    this.getMasterKey = () => {
      const cookie = Cookies.get('gravity-master-key');
      if (cookie === undefined) {
        throw new Error('No master key');
      }
      return sodium.from_base64(cookie);
    };

    this.encrypt = (key, message) => {
      // also prepends nonce
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      return uintConcat(nonce, sodium.crypto_secretbox_easy(message, nonce, key));
    };

    this.decrypt = (key, nonceAndCiphertext) => {
      if (!this.ready()) {
        throw new Error('Not ready yet');
      }
      if (nonceAndCiphertext.length
          < sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES) {
        throw new Error('Short message');
      }
      const nonce = nonceAndCiphertext.slice(0, sodium.crypto_secretbox_NONCEBYTES);
      const ciphertext = nonceAndCiphertext.slice(sodium.crypto_secretbox_NONCEBYTES);
      const m = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
      return sodium.to_string(m);
    };

    this.getNodeInfo = async () => {
      await this.readyAsync();
      return node.id()
    }

  }
}


module.exports = GravityProtocol;
